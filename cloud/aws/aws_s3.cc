//  Copyright (c) 2016-present, Rockset, Inc.  All rights reserved.
//
// This file defines an AWS-S3 environment for rocksdb.
// A directory maps to an an zero-size object in an S3 bucket
// A sst file maps to an object in that S3 bucket.
//
#ifdef USE_AWS

#include <assert.h>
#include <aws/core/Aws.h>
#include <aws/core/utils/Outcome.h>
#include <aws/core/utils/crypto/CryptoStream.h>
#include <aws/core/utils/memory/stl/AWSStreamFwd.h>
#include <aws/s3/S3Client.h>
#include <aws/s3/S3Errors.h>
#include <aws/s3/model/BucketLocationConstraint.h>
#include <aws/s3/model/CopyObjectRequest.h>
#include <aws/s3/model/CopyObjectResult.h>
#include <aws/s3/model/CreateBucketConfiguration.h>
#include <aws/s3/model/CreateBucketRequest.h>
#include <aws/s3/model/CreateBucketResult.h>
#include <aws/s3/model/DeleteBucketRequest.h>
#include <aws/s3/model/DeleteObjectRequest.h>
#include <aws/s3/model/DeleteObjectResult.h>
#include <aws/s3/model/GetBucketVersioningRequest.h>
#include <aws/s3/model/GetBucketVersioningResult.h>
#include <aws/s3/model/GetObjectRequest.h>
#include <aws/s3/model/GetObjectResult.h>
#include <aws/s3/model/HeadBucketRequest.h>
#include <aws/s3/model/HeadObjectRequest.h>
#include <aws/s3/model/HeadObjectResult.h>
#include <aws/s3/model/ListObjectsRequest.h>
#include <aws/s3/model/ListObjectsResult.h>
#include <aws/s3/model/PutObjectRequest.h>
#include <aws/s3/model/PutObjectResult.h>
#include <aws/s3/model/ServerSideEncryption.h>
#include <aws/transfer/TransferManager.h>

#include <cinttypes>
#include <fstream>
#include <iostream>

#include "cloud/aws/aws_file.h"
#include "cloud/cloud_storage_provider.h"
#include "cloud/filename.h"
#include "rocksdb/cloud/cloud_env_options.h"
#include "util/coding.h"
#include "util/stderr_logger.h"
#include "util/string_util.h"

namespace rocksdb {
class CloudRequestCallbackGuard {
 public:
  CloudRequestCallbackGuard(CloudRequestCallback* callback,
                            CloudRequestOpType type, uint64_t size = 0)
      : callback_(callback), type_(type), size_(size), start_(now()) {}

  ~CloudRequestCallbackGuard() {
    if (callback_) {
      (*callback_)(type_, size_, now() - start_, success_);
    }
  }

  void SetSize(uint64_t size) { size_ = size; }
  void SetSuccess(bool success) { success_ = success; }

 private:
  uint64_t now() {
    return std::chrono::duration_cast<std::chrono::microseconds>(
               std::chrono::system_clock::now() -
               std::chrono::system_clock::from_time_t(0))
        .count();
  }
  CloudRequestCallback* callback_;
  CloudRequestOpType type_;
  uint64_t size_;
  bool success_{false};
  uint64_t start_;
};

template <typename T>
void SetEncryptionParameters(const CloudEnvOptions& cloud_env_options,
                             T& put_request) {
  if (cloud_env_options.server_side_encryption) {
    if (cloud_env_options.encryption_key_id.empty()) {
      put_request.SetServerSideEncryption(
          Aws::S3::Model::ServerSideEncryption::AES256);
    } else {
      put_request.SetServerSideEncryption(
          Aws::S3::Model::ServerSideEncryption::aws_kms);
      put_request.SetSSEKMSKeyId(cloud_env_options.encryption_key_id.c_str());
    }
  }
}

/******************** S3ClientWrapper ******************/

class AwsS3ClientWrapper {
 public:
  AwsS3ClientWrapper(
      const std::shared_ptr<Aws::Auth::AWSCredentialsProvider>& creds,
      const Aws::Client::ClientConfiguration& config,
      const CloudEnvOptions& cloud_options)
      : cloud_request_callback_(cloud_options.cloud_request_callback) {
    if (creds) {
      client_ = std::make_shared<Aws::S3::S3Client>(creds, config);
    } else {
      client_ = std::make_shared<Aws::S3::S3Client>(config);
    }
    if (cloud_options.use_aws_transfer_manager) {
      Aws::Transfer::TransferManagerConfiguration transferManagerConfig(
          GetAwsTransferManagerExecutor());
      transferManagerConfig.s3Client = client_;
      SetEncryptionParameters(cloud_options,
                              transferManagerConfig.putObjectTemplate);
      SetEncryptionParameters(
          cloud_options, transferManagerConfig.createMultipartUploadTemplate);
      transfer_manager_ =
          Aws::Transfer::TransferManager::Create(transferManagerConfig);
    }
  }

  Aws::S3::Model::ListObjectsOutcome ListObjects(
      const Aws::S3::Model::ListObjectsRequest& request) {
    CloudRequestCallbackGuard t(cloud_request_callback_.get(),
                                CloudRequestOpType::kListOp);
    auto outcome = client_->ListObjects(request);
    t.SetSuccess(outcome.IsSuccess());
    return outcome;
  }

  Aws::S3::Model::CreateBucketOutcome CreateBucket(
      const Aws::S3::Model::CreateBucketRequest& request) {
    CloudRequestCallbackGuard t(cloud_request_callback_.get(),
                                CloudRequestOpType::kCreateOp);
    auto outcome = client_->CreateBucket(request);
    t.SetSuccess(outcome.IsSuccess());
    return outcome;
  }

  Aws::S3::Model::HeadBucketOutcome HeadBucket(
      const Aws::S3::Model::HeadBucketRequest& request) {
    CloudRequestCallbackGuard t(cloud_request_callback_.get(),
                                CloudRequestOpType::kInfoOp);
    auto outcome = client_->HeadBucket(request);
    t.SetSuccess(outcome.IsSuccess());
    return outcome;
  }
  Aws::S3::Model::DeleteObjectOutcome DeleteObject(
      const Aws::S3::Model::DeleteObjectRequest& request) {
    CloudRequestCallbackGuard t(cloud_request_callback_.get(),
                                CloudRequestOpType::kDeleteOp);
    auto outcome = client_->DeleteObject(request);
    t.SetSuccess(outcome.IsSuccess());
    return outcome;
  }

  Aws::S3::Model::CopyObjectOutcome CopyObject(
      const Aws::S3::Model::CopyObjectRequest& request) {
    CloudRequestCallbackGuard t(cloud_request_callback_.get(),
                                CloudRequestOpType::kCopyOp);
    auto outcome = client_->CopyObject(request);
    t.SetSuccess(outcome.IsSuccess());
    return outcome;
  }

  Aws::S3::Model::GetObjectOutcome GetObject(
      const Aws::S3::Model::GetObjectRequest& request) {
    CloudRequestCallbackGuard t(cloud_request_callback_.get(),
                                CloudRequestOpType::kReadOp);
    auto outcome = client_->GetObject(request);
    if (outcome.IsSuccess()) {
      t.SetSize(outcome.GetResult().GetContentLength());
      t.SetSuccess(true);
    }
    return outcome;
  }
  std::shared_ptr<Aws::Transfer::TransferHandle> DownloadFile(
      const Aws::String& bucket_name, const Aws::String& object_path,
      const Aws::String& destination) {
    CloudRequestCallbackGuard guard(cloud_request_callback_.get(),
                                    CloudRequestOpType::kReadOp);
    auto handle =
        transfer_manager_->DownloadFile(bucket_name, object_path, destination);

    handle->WaitUntilFinished();
    bool success =
        handle->GetStatus() == Aws::Transfer::TransferStatus::COMPLETED;
    guard.SetSuccess(success);
    if (success) {
      guard.SetSize(handle->GetBytesTotalSize());
    }
    return handle;
  }

  Aws::S3::Model::PutObjectOutcome PutObject(
      const Aws::S3::Model::PutObjectRequest& request, uint64_t size_hint = 0) {
    CloudRequestCallbackGuard t(cloud_request_callback_.get(),
                                CloudRequestOpType::kWriteOp, size_hint);
    auto outcome = client_->PutObject(request);
    t.SetSuccess(outcome.IsSuccess());
    return outcome;
  }

  std::shared_ptr<Aws::Transfer::TransferHandle> UploadFile(
      const Aws::String& bucket_name, const Aws::String& object_path,
      const Aws::String& destination, uint64_t file_size) {
    CloudRequestCallbackGuard guard(cloud_request_callback_.get(),
                                    CloudRequestOpType::kWriteOp, file_size);

    auto handle = transfer_manager_->UploadFile(
        destination, bucket_name, object_path, Aws::DEFAULT_CONTENT_TYPE,
        Aws::Map<Aws::String, Aws::String>());

    handle->WaitUntilFinished();
    guard.SetSuccess(handle->GetStatus() ==
                     Aws::Transfer::TransferStatus::COMPLETED);
    return handle;
  }

  Aws::S3::Model::HeadObjectOutcome HeadObject(
      const Aws::S3::Model::HeadObjectRequest& request) {
    CloudRequestCallbackGuard t(cloud_request_callback_.get(),
                                CloudRequestOpType::kInfoOp);
    auto outcome = client_->HeadObject(request);
    t.SetSuccess(outcome.IsSuccess());
    return outcome;
  }
  CloudRequestCallback* GetRequestCallback() {
    return cloud_request_callback_.get();
  }
  bool HasTransferManager() const { return transfer_manager_.get() != nullptr; }

 private:
  static Aws::Utils::Threading::Executor* GetAwsTransferManagerExecutor() {
    static Aws::Utils::Threading::PooledThreadExecutor executor(8);
    return &executor;
  }

  std::shared_ptr<Aws::S3::S3Client> client_;
  std::shared_ptr<Aws::Transfer::TransferManager> transfer_manager_;
  std::shared_ptr<CloudRequestCallback> cloud_request_callback_;
};

static bool IsNotFound(const Aws::S3::S3Errors& s3err) {
  return (s3err == Aws::S3::S3Errors::NO_SUCH_BUCKET ||
          s3err == Aws::S3::S3Errors::NO_SUCH_KEY ||
          s3err == Aws::S3::S3Errors::RESOURCE_NOT_FOUND);
}

/******************** S3ReadableFile ******************/
class S3ReadableFile : public CloudStorageReadableFile {
 public:
  S3ReadableFile(const std::shared_ptr<AwsS3ClientWrapper>& s3client,
                 const std::shared_ptr<Logger>& info_log,
                 const std::string& bucket, const std::string& fname,
                 uint64_t size)
      : CloudStorageReadableFile(info_log, bucket, fname, size),
        s3client_(s3client) {}

  virtual const char* Type() const { return "s3"; }

  // random access, read data from specified offset in file
  Status DoCloudRead(uint64_t offset, size_t n, char* scratch,
                     uint64_t* bytes_read) const override {
    // create a range read request
    // Ranges are inclusive, so we can't read 0 bytes; read 1 instead and
    // drop it later.
    size_t rangeLen = (n != 0 ? n : 1);
    char buffer[512];
    int ret = snprintf(buffer, sizeof(buffer), "bytes=%" PRIu64 "-%" PRIu64,
                       offset, offset + rangeLen - 1);
    if (ret < 0) {
      Log(InfoLogLevel::ERROR_LEVEL, info_log_,
          "[s3] S3ReadableFile vsnprintf error %s offset %" PRIu64
          " rangelen %" ROCKSDB_PRIszt "\n",
          fname_.c_str(), offset, rangeLen);
      return Status::IOError("S3ReadableFile vsnprintf ", fname_.c_str());
    }
    Aws::String range(buffer);

    // set up S3 request to read this range
    Aws::S3::Model::GetObjectRequest request;
    request.SetBucket(ToAwsString(bucket_));
    request.SetKey(ToAwsString(fname_));
    request.SetRange(range);

    Aws::S3::Model::GetObjectOutcome outcome = s3client_->GetObject(request);
    bool isSuccess = outcome.IsSuccess();
    if (!isSuccess) {
      const Aws::Client::AWSError<Aws::S3::S3Errors>& error =
          outcome.GetError();
      std::string errmsg(error.GetMessage().c_str(), error.GetMessage().size());
      if (IsNotFound(error.GetErrorType()) ||
          errmsg.find("Response code: 404") != std::string::npos) {
        Log(InfoLogLevel::ERROR_LEVEL, info_log_,
            "[s3] S3ReadableFile error in reading not-existent %s %s",
            fname_.c_str(), errmsg.c_str());
        return Status::NotFound(fname_, errmsg.c_str());
      }
      Log(InfoLogLevel::ERROR_LEVEL, info_log_,
          "[s3] S3ReadableFile error in reading %s %ld %s %s", fname_.c_str(),
          offset, buffer, error.GetMessage().c_str());
      return Status::IOError(fname_, errmsg.c_str());
    }
    std::stringstream ss;
    // const Aws::S3::Model::GetObjectResult& res = outcome.GetResult();

    // extract data payload
    Aws::IOStream& body = outcome.GetResult().GetBody();
    *bytes_read = 0;
    if (n != 0) {
      body.read(scratch, n);
      *bytes_read = body.gcount();
      assert(*bytes_read <= n);
    }
    Log(InfoLogLevel::DEBUG_LEVEL, info_log_,
        "[s3] S3ReadableFile file %s filesize %ld read %d bytes",
        fname_.c_str(), file_size_, *bytes_read);
    return Status::OK();
  }

 private:
  std::shared_ptr<AwsS3ClientWrapper> s3client_;
};  // End class S3ReadableFile

/******************** Writablefile ******************/

class S3WritableFile : public CloudStorageWritableFile {
 public:
  S3WritableFile(CloudEnv* env, const std::string& local_fname,
                 const std::string& bucket, const std::string& cloud_fname,
                 const EnvOptions& options)
      : CloudStorageWritableFile(env, local_fname, bucket, cloud_fname,
                                 options) {}
  virtual const char* Name() const override { return "s3"; }
};

/******************** S3StorageProvider ******************/
class S3StorageProvider : public CloudStorageProvider {
 public:
  S3StorageProvider(CloudEnv* env);
  ~S3StorageProvider() override {}
  Status CreateBucket(const std::string& bucket) override;
  Status ExistsBucket(const std::string& bucket) override;
  Status EmptyBucket(const std::string& bucket_name,
                     const std::string& object_path) override;
  // Empties all contents of the associated cloud storage bucket.
  // Status EmptyBucket(const std::string& bucket_name,
  //                   const std::string& object_path) override;
  // Delete the specified object from the specified cloud bucket
  Status DeleteObject(const std::string& bucket_name,
                      const std::string& object_path) override;
  Status ListObjects(const std::string& bucket_name,
                     const std::string& object_path,
                     std::vector<std::string>* result) override;
  Status ExistsObject(const std::string& bucket_name,
                      const std::string& object_path) override;
  Status GetObjectSize(const std::string& bucket_name,
                       const std::string& object_path,
                       uint64_t* filesize) override;
  // Get the modification time of the object in cloud storage
  Status GetObjectModificationTime(const std::string& bucket_name,
                                   const std::string& object_path,
                                   uint64_t* time) override;

  // Get the metadata of the object in cloud storage
  Status GetObjectMetadata(
      const std::string& bucket_name, const std::string& object_path,
      std::unordered_map<std::string, std::string>* metadata) override;
  Status PutObjectMetadata(
      const std::string& bucket_name, const std::string& object_path,
      const std::unordered_map<std::string, std::string>& metadata) override;
  Status CopyObject(const std::string& bucket_name_src,
                    const std::string& object_path_src,
                    const std::string& bucket_name_dest,
                    const std::string& object_path_dest) override;
  Status DoNewCloudReadableFile(
      const std::string& bucket, const std::string& fname, uint64_t fsize,
      unique_ptr<CloudStorageReadableFile>* result) override;
  Status NewCloudWritableFile(const std::string& local_path,
                              const std::string& bucket_name,
                              const std::string& object_path,
                              std::unique_ptr<CloudStorageWritableFile>* result,
                              const EnvOptions& options) override;
  Status SanitizeOptions() override;

 protected:
  Status DoGetObject(const std::string& bucket_name,
                     const std::string& object_path,
                     const std::string& destination,
                     uint64_t* remote_size) override;
  Status DoPutObject(const std::string& local_file,
                     const std::string& bucket_name,
                     const std::string& object_path,
                     uint64_t file_size) override;

 private:
  // If metadata, size or modtime is non-nullptr, returns requested data
  Status HeadObject(const std::string& bucket, const std::string& path,
                    Aws::Map<Aws::String, Aws::String>* metadata = nullptr,
                    uint64_t* size = nullptr, uint64_t* modtime = nullptr);
  // The S3 client
  std::shared_ptr<AwsS3ClientWrapper> s3client_;
  // AWS's utility to help out with uploading and downloading S3 file
  Aws::S3::Model::BucketLocationConstraint bucket_location_;
};

S3StorageProvider::S3StorageProvider(CloudEnv* env)
    : CloudStorageProvider(env) {}

Status S3StorageProvider::SanitizeOptions() {
  if (!status_.ok()) {
    return status_;
  }
  const CloudEnvOptions& cloud_opts = env_->GetCloudEnvOptions();
  // TODO: support buckets being in different regions
  if (!env_->SrcMatchesDest() && env_->HasSrcBucket() &&
      env_->HasDestBucket()) {
    if (cloud_opts.src_bucket.GetRegion() !=
        cloud_opts.dest_bucket.GetRegion()) {
      status_ = Status::InvalidArgument("Two different regions not supported");
      Log(InfoLogLevel::ERROR_LEVEL, env_->info_log_,
          "[aws] NewAwsEnv Buckets %s, %s in two different regions %s, %s "
          "is not supported",
          cloud_opts.src_bucket.GetBucketName().c_str(),
          cloud_opts.dest_bucket.GetBucketName().c_str(),
          cloud_opts.src_bucket.GetRegion().c_str(),
          cloud_opts.dest_bucket.GetRegion().c_str());
      return status_;
    }
  }
  Aws::Client::ClientConfiguration config;
  status_ = AwsCloudOptions::GetClientConfiguration(
      env_, cloud_opts.src_bucket.GetRegion(), &config);
  if (status_.ok()) {
    shared_ptr<Aws::Auth::AWSCredentialsProvider> creds;
    status_ = cloud_opts.credentials.GetCredentialsProvider(&creds);
    if (!status_.ok()) {
      Log(InfoLogLevel::INFO_LEVEL, env_->info_log_,
          "[aws] NewAwsEnv - Bad AWS credentials");
    } else {
      Header(env_->info_log_, "S3 connection to endpoint in region: %s",
             config.region.c_str());
      bucket_location_ = Aws::S3::Model::BucketLocationConstraintMapper::
          GetBucketLocationConstraintForName(config.region);
      s3client_ =
          std::make_shared<AwsS3ClientWrapper>(creds, config, cloud_opts);
    }
  }
  return CloudStorageProvider::SanitizeOptions();
}

//
// Create bucket in S3 if it does not already exist.
//
Status S3StorageProvider::CreateBucket(const std::string& bucket) {
  // specify region for the bucket
  Aws::S3::Model::CreateBucketConfiguration conf;
  if (bucket_location_ != Aws::S3::Model::BucketLocationConstraint::NOT_SET) {
    // only set the location constraint if it's not not set
    conf.SetLocationConstraint(bucket_location_);
  }

  // create bucket
  Aws::S3::Model::CreateBucketRequest request;
  request.SetBucket(ToAwsString(bucket));
  request.SetCreateBucketConfiguration(conf);
  Aws::S3::Model::CreateBucketOutcome outcome =
      s3client_->CreateBucket(request);
  bool isSuccess = outcome.IsSuccess();
  if (!isSuccess) {
    const Aws::Client::AWSError<Aws::S3::S3Errors>& error = outcome.GetError();
    std::string errmsg(error.GetMessage().c_str());
    Aws::S3::S3Errors s3err = error.GetErrorType();
    if (s3err != Aws::S3::S3Errors::BUCKET_ALREADY_EXISTS &&
        s3err != Aws::S3::S3Errors::BUCKET_ALREADY_OWNED_BY_YOU) {
      return Status::IOError(bucket.c_str(), errmsg.c_str());
    }
  }
  return Status::OK();
}

Status S3StorageProvider::ExistsBucket(const std::string& bucket) {
  Aws::S3::Model::HeadBucketRequest request;
  request.SetBucket(ToAwsString(bucket));
  Aws::S3::Model::HeadBucketOutcome outcome = s3client_->HeadBucket(request);
  return outcome.IsSuccess() ? Status::OK() : Status::NotFound();
}

//
// Deletes all the objects with the specified path prefix in our bucket
//
Status S3StorageProvider::EmptyBucket(const std::string& bucket_name,
                                      const std::string& object_path) {
  std::vector<std::string> results;

  // Get all the objects in the  bucket
  Status st = ListObjects(bucket_name, object_path, &results);
  if (!st.ok()) {
    Log(InfoLogLevel::ERROR_LEVEL, env_->info_log_,
        "[s3] EmptyBucket unable to find objects in bucket %s %s",
        bucket_name.c_str(), st.ToString().c_str());
    return st;
  }
  Log(InfoLogLevel::DEBUG_LEVEL, env_->info_log_,
      "[s3] EmptyBucket going to delete %d objects in bucket %s",
      results.size(), bucket_name.c_str());

  // Delete all objects from bucket
  for (auto path : results) {
    st = DeleteObject(bucket_name, path);
    if (!st.ok()) {
      Log(InfoLogLevel::ERROR_LEVEL, env_->info_log_,
          "[s3] EmptyBucket Unable to delete %s in bucket %s %s", path.c_str(),
          bucket_name.c_str(), st.ToString().c_str());
    }
  }
  return st;
}

Status S3StorageProvider::DeleteObject(const std::string& bucket_name,
                                       const std::string& object_path) {
  Status st;

  // create request
  Aws::S3::Model::DeleteObjectRequest request;
  request.SetBucket(ToAwsString(bucket_name));
  request.SetKey(ToAwsString(
      object_path));  // The filename is the object name in the bucket

  Aws::S3::Model::DeleteObjectOutcome outcome =
      s3client_->DeleteObject(request);
  bool isSuccess = outcome.IsSuccess();
  if (!isSuccess) {
    const Aws::Client::AWSError<Aws::S3::S3Errors>& error = outcome.GetError();
    std::string errmsg(error.GetMessage().c_str());
    if (IsNotFound(error.GetErrorType())) {
      st = Status::NotFound(object_path, errmsg.c_str());
    } else {
      st = Status::IOError(object_path, errmsg.c_str());
    }
  }

  Log(InfoLogLevel::INFO_LEVEL, env_->info_log_,
      "[s3] DeleteFromS3 %s/%s, status %s", bucket_name.c_str(),
      object_path.c_str(), st.ToString().c_str());

  return st;
}

//
// Appends the names of all children of the specified path from S3
// into the result set.
//
Status S3StorageProvider::ListObjects(const std::string& bucket_name,
                                      const std::string& object_path,
                                      std::vector<std::string>* result) {
  // S3 paths don't start with '/'
  auto prefix = ltrim_if(object_path, '/');
  // S3 paths better end with '/', otherwise we might also get a list of files
  // in a directory for which our path is a prefix
  prefix = ensure_ends_with_pathsep(std::move(prefix));
  // the starting object marker
  Aws::String marker;
  bool loop = true;

  // get info of bucket+object
  while (loop) {
    Aws::S3::Model::ListObjectsRequest request;
    request.SetBucket(ToAwsString(bucket_name));
    request.SetMaxKeys(50);
    request.SetPrefix(ToAwsString(prefix));
    request.SetMarker(marker);

    Aws::S3::Model::ListObjectsOutcome outcome =
        s3client_->ListObjects(request);
    bool isSuccess = outcome.IsSuccess();
    if (!isSuccess) {
      const Aws::Client::AWSError<Aws::S3::S3Errors>& error =
          outcome.GetError();
      std::string errmsg(error.GetMessage().c_str());
      if (IsNotFound(error.GetErrorType())) {
        Log(InfoLogLevel::ERROR_LEVEL, env_->info_log_,
            "[s3] GetChildren dir %s does not exist", object_path.c_str(),
            errmsg.c_str());
        return Status::NotFound(object_path, errmsg.c_str());
      }
      return Status::IOError(object_path, errmsg.c_str());
    }
    const Aws::S3::Model::ListObjectsResult& res = outcome.GetResult();
    const Aws::Vector<Aws::S3::Model::Object>& objs = res.GetContents();
    for (auto o : objs) {
      const Aws::String& key = o.GetKey();
      // Our path should be a prefix of the fetched value
      std::string keystr(key.c_str(), key.size());
      assert(keystr.find(prefix) == 0);
      if (keystr.find(prefix) != 0) {
        return Status::IOError("Unexpected result from AWS S3: " + keystr);
      }
      auto fname = keystr.substr(prefix.size());
      result->push_back(fname);
    }

    // If there are no more entries, then we are done.
    if (!res.GetIsTruncated()) {
      break;
    }
    // The new starting point
    marker = res.GetNextMarker();
    if (marker.empty()) {
      // If response does not include the NextMaker and it is
      // truncated, you can use the value of the last Key in the response
      // as the marker in the subsequent request because all objects
      // are returned in alphabetical order
      marker = objs.back().GetKey();
    }
  }
  return Status::OK();
}
// Delete the specified object from the specified cloud bucket
Status S3StorageProvider::ExistsObject(const std::string& bucket_name,
                                       const std::string& object_path) {
  Status s = HeadObject(bucket_name, object_path);
  return s;
}

// Return size of cloud object
Status S3StorageProvider::GetObjectSize(const std::string& bucket_name,
                                        const std::string& object_path,
                                        uint64_t* filesize) {
  Status s = HeadObject(bucket_name, object_path, nullptr, filesize, nullptr);
  return s;
}

Status S3StorageProvider::GetObjectModificationTime(
    const std::string& bucket_name, const std::string& object_path,
    uint64_t* time) {
  return HeadObject(bucket_name, object_path, nullptr, nullptr, time);
}

Status S3StorageProvider::GetObjectMetadata(
    const std::string& bucket_name, const std::string& object_path,
    std::unordered_map<std::string, std::string>* result) {
  Aws::Map<Aws::String, Aws::String> metadata;
  Status st = HeadObject(bucket_name, object_path, &metadata, nullptr, nullptr);
  if (st.ok()) {
    for (const auto m : metadata) {
      (*result)[m.first.c_str()] = m.second.c_str();
    }
  }
  return st;
}

Status S3StorageProvider::PutObjectMetadata(
    const std::string& bucket_name, const std::string& object_path,
    const std::unordered_map<std::string, std::string>& metadata) {
  Aws::S3::Model::PutObjectRequest request;
  Aws::Map<Aws::String, Aws::String> aws_metadata;
  for (const auto m : metadata) {
    aws_metadata[ToAwsString(m.first)] = ToAwsString(m.second);
  }
  request.SetBucket(ToAwsString(bucket_name));
  request.SetKey(ToAwsString(object_path));
  request.SetMetadata(aws_metadata);
  SetEncryptionParameters(env_->GetCloudEnvOptions(), request);

  auto outcome = s3client_->PutObject(request);
  bool isSuccess = outcome.IsSuccess();
  if (!isSuccess) {
    const auto& error = outcome.GetError();
    std::string errmsg(error.GetMessage().c_str(), error.GetMessage().size());
    Log(InfoLogLevel::ERROR_LEVEL, env_->info_log_,
        "[s3] Bucket %s error in saving metadata %s %s", bucket_name.c_str(),
        errmsg.c_str());
    return Status::IOError(object_path, errmsg.c_str());
  }
  return Status::OK();
}

Status S3StorageProvider::DoNewCloudReadableFile(
    const std::string& bucket, const std::string& fname, uint64_t fsize,
    unique_ptr<CloudStorageReadableFile>* result) {
  result->reset(
      new S3ReadableFile(s3client_, env_->info_log_, bucket, fname, fsize));
  return Status::OK();
}

Status S3StorageProvider::NewCloudWritableFile(
    const std::string& local_path, const std::string& bucket_name,
    const std::string& object_path,
    std::unique_ptr<CloudStorageWritableFile>* result,
    const EnvOptions& options) {
  result->reset(
      new S3WritableFile(env_, local_path, bucket_name, object_path, options));
  return (*result)->status();
}

Status S3StorageProvider::HeadObject(
    const std::string& bucket_name, const std::string& object_path,
    Aws::Map<Aws::String, Aws::String>* metadata, uint64_t* size,
    uint64_t* modtime) {
  Aws::S3::Model::HeadObjectRequest request;
  request.SetBucket(ToAwsString(bucket_name));
  request.SetKey(ToAwsString(object_path));

  auto outcome = s3client_->HeadObject(request);
  bool isSuccess = outcome.IsSuccess();
  if (!isSuccess) {
    const auto& error = outcome.GetError();
    auto errMessage = error.GetMessage();
    if (IsNotFound(error.GetErrorType())) {
      return Status::NotFound(object_path, errMessage.c_str());
    }
    return Status::IOError(object_path, errMessage.c_str());
  }
  auto& res = outcome.GetResult();
  if (metadata != nullptr) {
    *metadata = res.GetMetadata();
  }
  if (size != nullptr) {
    *size = res.GetContentLength();
  }
  if (modtime != nullptr) {
    *modtime = res.GetLastModified().Millis();
  }
  return Status::OK();
}

// Copy the specified cloud object from one location in the cloud
// storage to another location in cloud storage
Status S3StorageProvider::CopyObject(const std::string& bucket_name_src,
                                     const std::string& object_path_src,
                                     const std::string& bucket_name_dest,
                                     const std::string& object_path_dest) {
  Status st;
  Aws::String src_bucket = ToAwsString(bucket_name_src);
  Aws::String dest_bucket = ToAwsString(bucket_name_dest);

  // The filename is the same as the object name in the bucket
  Aws::String src_object = ToAwsString(object_path_src);
  Aws::String dest_object = ToAwsString(object_path_dest);

  Aws::String src_url = src_bucket + src_object;

  // create copy request
  Aws::S3::Model::CopyObjectRequest request;
  request.SetCopySource(src_url);
  request.SetBucket(dest_bucket);
  request.SetKey(dest_object);

  // execute request
  Aws::S3::Model::CopyObjectOutcome outcome = s3client_->CopyObject(request);
  bool isSuccess = outcome.IsSuccess();
  if (!isSuccess) {
    const Aws::Client::AWSError<Aws::S3::S3Errors>& error = outcome.GetError();
    std::string errmsg(error.GetMessage().c_str());
    Log(InfoLogLevel::ERROR_LEVEL, env_->info_log_,
        "[s3] S3WritableFile src path %s error in copying to %s %s",
        src_url.c_str(), dest_object.c_str(), errmsg.c_str());
    return Status::IOError(dest_object.c_str(), errmsg.c_str());
  }
  Log(InfoLogLevel::ERROR_LEVEL, env_->info_log_,
      "[s3] S3WritableFile src path %s copied to %s %s", src_url.c_str(),
      dest_object.c_str(), st.ToString().c_str());
  return st;
}

Status S3StorageProvider::DoGetObject(const std::string& bucket_name,
                                      const std::string& object_path,
                                      const std::string& destination,
                                      uint64_t* remote_size) {
  if (s3client_->HasTransferManager()) {
    auto handle = s3client_->DownloadFile(ToAwsString(bucket_name),
                                          ToAwsString(object_path),
                                          ToAwsString(destination));
    bool success =
        handle->GetStatus() == Aws::Transfer::TransferStatus::COMPLETED;
    if (success) {
      *remote_size = handle->GetBytesTotalSize();
    } else {
      const auto& error = handle->GetLastError();
      std::string errmsg(error.GetMessage().c_str(), error.GetMessage().size());
      Log(InfoLogLevel::ERROR_LEVEL, env_->info_log_,
          "[s3] DownloadFile %s/%s error %s.", bucket_name.c_str(),
          object_path.c_str(), errmsg.c_str());
      if (IsNotFound(error.GetErrorType())) {
        return Status::NotFound(std::move(errmsg));
      }
      return Status::IOError(std::move(errmsg));
    }
  } else {
    Aws::S3::Model::GetObjectRequest request;
    request.SetBucket(ToAwsString(bucket_name));
    request.SetKey(ToAwsString(object_path));

    request.SetResponseStreamFactory([destination]() {
      return Aws::New<Aws::FStream>(Aws::Utils::ARRAY_ALLOCATION_TAG,
                                    destination, std::ios_base::out);
    });
    auto outcome = s3client_->GetObject(request);
    if (outcome.IsSuccess()) {
      *remote_size = outcome.GetResult().GetContentLength();
    } else {
      const auto& error = outcome.GetError();
      std::string errmsg(error.GetMessage().c_str(), error.GetMessage().size());
      Log(InfoLogLevel::ERROR_LEVEL, env_->info_log_,
          "[s3] GetObject %s/%s error %s.", bucket_name.c_str(),
          object_path.c_str(), errmsg.c_str());
      if (IsNotFound(error.GetErrorType())) {
        return Status::NotFound(std::move(errmsg));
      }
      return Status::IOError(std::move(errmsg));
    }
  }
  return Status::OK();
}

Status S3StorageProvider::DoPutObject(const std::string& local_file,
                                      const std::string& bucket_name,
                                      const std::string& object_path,
                                      uint64_t file_size) {
  if (s3client_->HasTransferManager()) {
    auto handle =
        s3client_->UploadFile(ToAwsString(local_file), ToAwsString(bucket_name),
                              ToAwsString(object_path), file_size);
    if (handle->GetStatus() != Aws::Transfer::TransferStatus::COMPLETED) {
      auto error = handle->GetLastError();
      std::string errmsg(error.GetMessage().c_str(), error.GetMessage().size());
      Log(InfoLogLevel::ERROR_LEVEL, env_->info_log_,
          "[s3] UploadFile %s/%s, size %zu, ERROR %s", bucket_name.c_str(),
          object_path.c_str(), file_size, errmsg.c_str());
      return Status::IOError(local_file, errmsg);
    }
  } else {
    auto inputData =
        Aws::MakeShared<Aws::FStream>(object_path.c_str(), local_file.c_str(),
                                      std::ios_base::in | std::ios_base::out);

    Aws::S3::Model::PutObjectRequest putRequest;
    putRequest.SetBucket(ToAwsString(bucket_name));
    putRequest.SetKey(ToAwsString(object_path));
    putRequest.SetBody(inputData);
    SetEncryptionParameters(env_->GetCloudEnvOptions(), putRequest);

    auto outcome = s3client_->PutObject(putRequest, file_size);
    if (!outcome.IsSuccess()) {
      auto error = outcome.GetError();
      std::string errmsg(error.GetMessage().c_str(), error.GetMessage().size());
      Log(InfoLogLevel::ERROR_LEVEL, env_->info_log_,
          "[s3] PutObject %s/%s, size %zu, ERROR %s", bucket_name.c_str(),
          object_path.c_str(), file_size, errmsg.c_str());
      return Status::IOError(local_file, errmsg);
    }
  }
  Log(InfoLogLevel::INFO_LEVEL, env_->info_log_,
      "[s3] PutObject %s/%s, size %zu, OK", bucket_name.c_str(),
      object_path.c_str(), file_size);
  return Status::OK();
}

Status CloudStorageProvider::LoadStorageProvider(
    CloudEnv* env, const std::string& value,
    std::unique_ptr<CloudStorageProvider>* result) {
  if (value == "s3") {
    result->reset(new S3StorageProvider(env));
  } else {
    return Status::NotFound();
  }
  return Status::OK();
}
}  // namespace

#endif /* USE_AWS */
