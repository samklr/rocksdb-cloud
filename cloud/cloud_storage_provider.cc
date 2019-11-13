//  Copyright (c) 2016-present, Rockset, Inc.  All rights reserved.
//

#include "cloud/cloud_storage_provider.h"

#include <inttypes.h>

#include <mutex>
#include <set>

#include "cloud/cloud_env_impl.h"
#include "cloud/filename.h"
#include "rocksdb/cloud/cloud_env_options.h"
#include "rocksdb/env.h"
#include "rocksdb/status.h"
#include "util/coding.h"
#include "util/filename.h"
#include "util/stderr_logger.h"
#include "util/string_util.h"

namespace rocksdb {

/******************** Readablefile ******************/
CloudStorageReadableFile::CloudStorageReadableFile(
    const std::shared_ptr<Logger>& info_log, const std::string& bucket,
    const std::string& fname, uint64_t file_size)
    : info_log_(info_log),
      bucket_(bucket),
      fname_(fname),
      offset_(0),
      file_size_(file_size) {
  Log(InfoLogLevel::DEBUG_LEVEL, info_log_,
      "[%s] CloudReadableFile opening file %s", Name(), fname_.c_str());
}

// sequential access, read data at current offset in file
Status CloudStorageReadableFile::Read(size_t n, Slice* result, char* scratch) {
  Log(InfoLogLevel::DEBUG_LEVEL, info_log_,
      "[%s] CloudReadableFile reading %s %ld", Name(), fname_.c_str(), n);
  Status s = Read(offset_, n, result, scratch);

  // If the read successfully returned some data, then update
  // offset_
  if (s.ok()) {
    offset_ += result->size();
  }
  return s;
}

// random access, read data from specified offset in file
Status CloudStorageReadableFile::Read(uint64_t offset, size_t n, Slice* result,
                                      char* scratch) const {
  Log(InfoLogLevel::DEBUG_LEVEL, info_log_,
      "[%s] CloudReadableFile reading %s at offset %ld size %ld", Name(),
      fname_.c_str(), offset, n);

  *result = Slice();

  if (offset >= file_size_) {
    Log(InfoLogLevel::DEBUG_LEVEL, info_log_,
        "[%s] CloudReadableFile reading %s at offset %" PRIu64
        " filesize %ld."
        " Nothing to do",
        Name(), fname_.c_str(), offset, file_size_);
    return Status::OK();
  }

  // trim size if needed
  if (offset + n > file_size_) {
    n = file_size_ - offset;
    Log(InfoLogLevel::DEBUG_LEVEL, info_log_,
        "[%s] CloudReadableFile reading %s at offset %" PRIu64
        " trimmed size %ld",
        Name(), fname_.c_str(), offset, n);
  }
  uint64_t bytes_read;
  Status st = DoCloudRead(offset, n, scratch, &bytes_read);
  if (st.ok()) {
    *result = Slice(scratch, bytes_read);
    Log(InfoLogLevel::DEBUG_LEVEL, info_log_,
        "[%s] CloudReadableFile file %s filesize %ld read %d bytes", Name(),
        fname_.c_str(), file_size_, bytes_read);
  }
  return st;
}

Status CloudStorageReadableFile::Skip(uint64_t n) {
  Log(InfoLogLevel::DEBUG_LEVEL, info_log_,
      "[%s] CloudReadableFile file %s skip %ld", Name(), fname_.c_str(), n);
  // Update offset_ so that it does not go beyond filesize
  offset_ += n;
  if (offset_ > file_size_) {
    offset_ = file_size_;
  }
  return Status::OK();
}

size_t CloudStorageReadableFile::GetUniqueId(char* id, size_t max_size) const {
  // If this is an SST file name, then it can part of the persistent cache.
  // We need to generate a unique id for the cache.
  // If it is not a sst file, then nobody should be using this id.
  uint64_t file_number;
  FileType file_type;
  WalFileType log_type;
  ParseFileName(RemoveEpoch(basename(fname_)), &file_number, &file_type,
                &log_type);
  if (max_size < kMaxVarint64Length && file_number > 0) {
    char* rid = id;
    rid = EncodeVarint64(rid, file_number);
    return static_cast<size_t>(rid - id);
  }
  return 0;
}

/******************** Writablefile ******************/

CloudStorageWritableFile::CloudStorageWritableFile(
    CloudEnv* env, const std::string& local_fname, const std::string& bucket,
    const std::string& cloud_fname, const EnvOptions& options)
    : env_(env),
      fname_(local_fname),
      bucket_(bucket),
      cloud_fname_(cloud_fname) {
  auto fname_no_epoch = RemoveEpoch(fname_);
  // Is this a manifest file?
  is_manifest_ = IsManifestFile(fname_no_epoch);
  assert(IsSstFile(fname_no_epoch) || is_manifest_);

  Log(InfoLogLevel::DEBUG_LEVEL, env_->info_log_,
      "[%s] CloudWritableFile bucket %s opened local file %s "
      "cloud file %s manifest %d",
      Name(), bucket.c_str(), fname_.c_str(), cloud_fname.c_str(),
      is_manifest_);

  auto* file_to_open = &fname_;
  auto local_env = env_->GetBaseEnv();
  Status s;
  if (is_manifest_) {
    s = local_env->FileExists(fname_);
    if (!s.ok() && !s.IsNotFound()) {
      status_ = s;
      return;
    }
    if (s.ok()) {
      // Manifest exists. Instead of overwriting the MANIFEST (which could be
      // bad if we crash mid-write), write to the temporary file and do an
      // atomic rename on Sync() (Sync means we have a valid data in the
      // MANIFEST, so we can crash after it)
      tmp_file_ = fname_ + ".tmp";
      file_to_open = &tmp_file_;
    }
  }

  s = local_env->NewWritableFile(*file_to_open, &local_file_, options);
  if (!s.ok()) {
    Log(InfoLogLevel::ERROR_LEVEL, env_->info_log_,
        "[%s] CloudWritableFile src %s %s", Name(), fname_.c_str(),
        s.ToString().c_str());
    status_ = s;
  }
}

CloudStorageWritableFile::~CloudStorageWritableFile() {
  if (local_file_ != nullptr) {
    Close();
  }
}

Status CloudStorageWritableFile::Close() {
  if (local_file_ == nullptr) {  // already closed
    return status_;
  }
  Log(InfoLogLevel::DEBUG_LEVEL, env_->info_log_,
      "[%s] CloudWritableFile closing %s", Name(), fname_.c_str());
  assert(status_.ok());

  // close local file
  Status st = local_file_->Close();
  if (!st.ok()) {
    Log(InfoLogLevel::ERROR_LEVEL, env_->info_log_,
        "[%s] CloudWritableFile closing error on local %s\n", Name(),
        fname_.c_str());
    return st;
  }
  local_file_.reset();

  if (!is_manifest_) {
    status_ = env_->CopyLocalFileToDest(fname_, cloud_fname_);
    if (!status_.ok()) {
      Log(InfoLogLevel::ERROR_LEVEL, env_->info_log_,
          "[%s] CloudWritableFile closing PutObject failed on local file %s",
          Name(), fname_.c_str());
      return status_;
    }

    // delete local file
    if (!env_->GetCloudEnvOptions().keep_local_sst_files) {
      status_ = env_->GetBaseEnv()->DeleteFile(fname_);
      if (!status_.ok()) {
        Log(InfoLogLevel::ERROR_LEVEL, env_->info_log_,
            "[%s] CloudWritableFile closing delete failed on local file %s",
            Name(), fname_.c_str());
        return status_;
      }
    }
    Log(InfoLogLevel::DEBUG_LEVEL, env_->info_log_,
        "[%s] CloudWritableFile closed file %s", Name(), fname_.c_str());
  }
  return Status::OK();
}

// Sync a file to stable storage
Status CloudStorageWritableFile::Sync() {
  if (local_file_ == nullptr) {
    return status_;
  }
  assert(status_.ok());

  // sync local file
  Status stat = local_file_->Sync();

  if (stat.ok() && !tmp_file_.empty()) {
    assert(is_manifest_);
    // We are writing to the temporary file. On a first sync we need to rename
    // the file to the real filename.
    stat = env_->GetBaseEnv()->RenameFile(tmp_file_, fname_);
    // Note: this is not thread safe, but we know that manifest writes happen
    // from the same thread, so we are fine.
    tmp_file_.clear();
  }

  // We copy MANIFEST to S3 on every Sync()
  if (is_manifest_ && stat.ok()) {
    stat = env_->CopyLocalFileToDest(fname_, cloud_fname_);
    if (stat.ok()) {
      Log(InfoLogLevel::DEBUG_LEVEL, env_->info_log_,
          "[s3] S3WritableFile made manifest %s durable to "
          "bucket %s bucketpath %s.",
          fname_.c_str(), bucket_.c_str(), cloud_fname_.c_str());
    } else {
      Log(InfoLogLevel::ERROR_LEVEL, env_->info_log_,
          "[s3] S3WritableFile failed to make manifest %s durable to "
          "bucket %s bucketpath. %s",
          fname_.c_str(), bucket_.c_str(), cloud_fname_.c_str(),
          stat.ToString().c_str());
    }
  }
  return stat;
}

CloudStorageProvider::CloudStorageProvider(CloudEnv* env) : env_(env) {}

CloudStorageProvider::~CloudStorageProvider() {}

Status CloudStorageProvider::SanitizeOptions() {
  if (!status_.ok()) {
    return status_;
  } else if (env_->HasDestBucket()) {
    // create dest bucket if specified
    if (ExistsBucket(env_->GetDestBucketName()).ok()) {
      Log(InfoLogLevel::INFO_LEVEL, env_->info_log_,
          "[%s] Bucket %s already exists", Name(),
          env_->GetDestBucketName().c_str());
    } else if (env_->GetCloudEnvOptions().create_bucket_if_missing) {
      Log(InfoLogLevel::INFO_LEVEL, env_->info_log_,
          "[s3] Going to create bucket %s", env_->GetDestBucketName().c_str());
      status_ = CreateBucket(env_->GetDestBucketName());
    } else {
      status_ = Status::NotFound(
          "Bucket not found and create_bucket_if_missing is false");
    }
    if (!status_.ok()) {
      Log(InfoLogLevel::ERROR_LEVEL, env_->info_log_,
          "[aws] NewAwsEnv Unable to create bucket %s %s",
          env_->GetDestBucketName().c_str(), status_.ToString().c_str());
      return status_;
    }
  }
  return status_;
}

Status CloudStorageProvider::NewCloudReadableFile(
    const std::string& bucket, const std::string& fname,
    unique_ptr<CloudStorageReadableFile>* result) {
  // First, check if the file exists and also find its size. We use size in
  // S3ReadableFile to make sure we always read the valid ranges of the file
  uint64_t size;
  Status st = GetObjectSize(bucket, fname, &size);
  if (!st.ok()) {
    return st;
  }
  return DoNewCloudReadableFile(bucket, fname, size, result);
}

Status CloudStorageProvider::GetObject(const std::string& bucket_name,
                                       const std::string& object_path,
                                       const std::string& local_destination) {
  Env* localenv = env_->GetBaseEnv();
  std::string tmp_destination = local_destination + ".tmp";
  uint64_t remote_size;
  Status s =
      DoGetObject(bucket_name, object_path, tmp_destination, &remote_size);
  if (!s.ok()) {
    localenv->DeleteFile(tmp_destination);
    return s;
  }

  // Check if our local file is the same as promised
  uint64_t local_size{0};
  s = localenv->GetFileSize(tmp_destination, &local_size);
  if (!s.ok()) {
    return s;
  }
  if (local_size != remote_size) {
    localenv->DeleteFile(tmp_destination);
    s = Status::IOError("Partial download of a file " + local_destination);
    Log(InfoLogLevel::ERROR_LEVEL, env_->info_log_,
        "[aws] GetObject %s/%s local size %ld != cloud size "
        "%ld. %s",
        bucket_name.c_str(), object_path.c_str(), local_size, remote_size,
        s.ToString().c_str());
  }

  if (s.ok()) {
    s = localenv->RenameFile(tmp_destination, local_destination);
  }
  Log(InfoLogLevel::INFO_LEVEL, env_->info_log_,
      "[%s] GetObject %s/%s size %ld. %s", bucket_name.c_str(), Name(),
      object_path.c_str(), local_size, s.ToString().c_str());
  return s;
}

Status CloudStorageProvider::PutObject(const std::string& local_file,
                                       const std::string& bucket_name,
                                       const std::string& object_path) {
  uint64_t fsize = 0;
  // debugging paranoia. Files uploaded to S3 can never be zero size.
  auto st = env_->GetBaseEnv()->GetFileSize(local_file, &fsize);
  if (!st.ok()) {
    Log(InfoLogLevel::ERROR_LEVEL, env_->info_log_,
        "[%s] PutObject localpath %s error getting size %s", Name(),
        local_file.c_str(), st.ToString().c_str());
    return st;
  }
  if (fsize == 0) {
    Log(InfoLogLevel::ERROR_LEVEL, env_->info_log_,
        "[%s] PutObject localpath %s error zero size", Name(),
        local_file.c_str());
    return Status::IOError(local_file + " Zero size.");
  }

  return DoPutObject(local_file, bucket_name, object_path, fsize);
}
}  // namespace rocksdb
