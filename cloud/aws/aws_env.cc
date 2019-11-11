//  Copyright (c) 2016-present, Rockset, Inc.  All rights reserved.
//
#include "cloud/aws/aws_env.h"
#include <unistd.h>
#include <chrono>
#include <fstream>
#include <iostream>
#include <memory>
#include "rocksdb/env.h"
#include "rocksdb/status.h"
#include "util/stderr_logger.h"
#include "util/string_util.h"

#ifdef USE_AWS
#include <aws/core/auth/AWSCredentialsProvider.h>
#include <aws/core/utils/threading/Executor.h>
#endif

#include "cloud/aws/aws_env.h"
#include "cloud/aws/aws_file.h"
#include "cloud/cloud_log_controller.h"
#include "cloud/cloud_storage_provider.h"
#include "cloud/db_cloud_impl.h"
#include "cloud/filename.h"

namespace rocksdb {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

static const std::unordered_map<std::string, AwsAccessType> AwsAccessTypeMap = {
    {"undefined", AwsAccessType::kUndefined},
    {"simple", AwsAccessType::kSimple},
    {"instance", AwsAccessType::kInstance},
    {"EC2", AwsAccessType::kInstance},
    {"environment", AwsAccessType::kEnvironment},
    {"config", AwsAccessType::kConfig},
    {"anonymous", AwsAccessType::kAnonymous},
};

template <typename T>
bool ParseEnum(const std::unordered_map<std::string, T>& type_map,
               const std::string& type, T* value) {
  auto iter = type_map.find(type);
  if (iter != type_map.end()) {
    *value = iter->second;
    return true;
  }
  return false;
}

AwsAccessType AwsCloudAccessCredentials::GetAccessType() const {
  if (type != AwsAccessType::kUndefined) {
    return type;
  } else if (!config_file.empty()) {
    return AwsAccessType::kConfig;
  } else if (!access_key_id.empty() || !secret_key.empty()) {
    return AwsAccessType::kSimple;
  }
  return AwsAccessType::kUndefined;
}

Status AwsCloudAccessCredentials::TEST_Initialize() {
  std::string type_str;
  if (CloudEnvOptions::GetNameFromEnvironment(
          "ROCKSDB_AWS_ACCESS_TYPE", "rocksdb_aws_access_type", &type_str)) {
    ParseEnum<AwsAccessType>(AwsAccessTypeMap, type_str, &type);
  }
  return HasValid();
}

Status AwsCloudAccessCredentials::CheckCredentials(
    const AwsAccessType& aws_type) const {
#ifndef USE_AWS
  return Status::NotSupported("AWS not supported");
#else
  if (aws_type == AwsAccessType::kSimple) {
    if ((access_key_id.empty() && getenv("AWS_ACCESS_KEY_ID") == nullptr) ||
        (secret_key.empty() && getenv("AWS_SECRET_ACCESS_KEY") == nullptr)) {
      return Status::InvalidArgument(
          "AWS Credentials require both access ID and secret keys");
    }
  } else if (aws_type == AwsAccessType::kTaskRole) {
    return Status::InvalidArgument(
        "AWS access type: Task Role access is not supported.");
  }
  return Status::OK();
#endif
}

void AwsCloudAccessCredentials::InitializeSimple(
    const std::string& aws_access_key_id, const std::string& aws_secret_key) {
  type = AwsAccessType::kSimple;
  access_key_id = aws_access_key_id;
  secret_key = aws_secret_key;
}

void AwsCloudAccessCredentials::InitializeConfig(
    const std::string& aws_config_file) {
  type = AwsAccessType::kConfig;
  config_file = aws_config_file;
}

Status AwsCloudAccessCredentials::HasValid() const {
  AwsAccessType aws_type = GetAccessType();
  Status status = CheckCredentials(aws_type);
  return status;
}

Status AwsCloudAccessCredentials::GetCredentialsProvider(
    std::shared_ptr<Aws::Auth::AWSCredentialsProvider>* result) const {
  result->reset();

  AwsAccessType aws_type = GetAccessType();
  Status status = CheckCredentials(aws_type);
  if (status.ok()) {
    switch (aws_type) {
#ifdef USE_AWS
      case AwsAccessType::kSimple: {
        const char* access_key =
            (access_key_id.empty() ? getenv("AWS_ACCESS_KEY_ID")
                                   : access_key_id.c_str());
        const char* secret =
            (secret_key.empty() ? getenv("AWS_SECRET_ACCESS_KEY")
                                : secret_key.c_str());
        result->reset(
            new Aws::Auth::SimpleAWSCredentialsProvider(access_key, secret));
        break;
      }
      case AwsAccessType::kConfig:
        if (!config_file.empty()) {
          result->reset(new Aws::Auth::ProfileConfigFileAWSCredentialsProvider(
              config_file.c_str()));
        } else {
          result->reset(
              new Aws::Auth::ProfileConfigFileAWSCredentialsProvider());
        }
        break;
      case AwsAccessType::kInstance:
        result->reset(new Aws::Auth::InstanceProfileCredentialsProvider());
        break;
      case AwsAccessType::kAnonymous:
        result->reset(new Aws::Auth::AnonymousAWSCredentialsProvider());
        break;
      case AwsAccessType::kEnvironment:
        result->reset(new Aws::Auth::EnvironmentAWSCredentialsProvider());
        break;
      case AwsAccessType::kUndefined:
        // Use AWS SDK's default credential chain
        result->reset();
        break;
#endif
      default:
        status = Status::NotSupported("AWS credentials type not supported");
        break;  // not supported
    }
  }
  return status;
}

#ifdef USE_AWS
void AwsEnv::Shutdown() { Aws::ShutdownAPI(Aws::SDKOptions()); }

//
// The AWS credentials are specified to the constructor via
// access_key_id and secret_key.
//
AwsEnv::AwsEnv(Env* underlying_env, const CloudEnvOptions& _cloud_env_options,
               const std::shared_ptr<Logger>& info_log)
    : CloudEnvImpl(_cloud_env_options, underlying_env, info_log) {
  Aws::InitAPI(Aws::SDKOptions());
  if (cloud_env_options.src_bucket.GetRegion().empty() ||
      cloud_env_options.dest_bucket.GetRegion().empty()) {
    std::string region;
    if (! CloudEnvOptions::GetNameFromEnvironment("AWS_DEFAULT_REGION", "aws_default_region", &region)) {
      region = default_region;
    }
    if (cloud_env_options.src_bucket.GetRegion().empty()) {
      cloud_env_options.src_bucket.SetRegion(region);
    }
    if (cloud_env_options.dest_bucket.GetRegion().empty()) {
      cloud_env_options.dest_bucket.SetRegion(region);
    }
  }

  shared_ptr<Aws::Auth::AWSCredentialsProvider> creds;
  create_bucket_status_ =
      cloud_env_options.credentials.GetCredentialsProvider(&creds);
  if (!create_bucket_status_.ok()) {
    Log(InfoLogLevel::INFO_LEVEL, info_log,
        "[aws] NewAwsEnv - Bad AWS credentials");
  }

  Header(info_log_, "      AwsEnv.src_bucket_name: %s",
         cloud_env_options.src_bucket.GetBucketName().c_str());
  Header(info_log_, "      AwsEnv.src_object_path: %s",
         cloud_env_options.src_bucket.GetObjectPath().c_str());
  Header(info_log_, "      AwsEnv.src_bucket_region: %s",
         cloud_env_options.src_bucket.GetRegion().c_str());
  Header(info_log_, "     AwsEnv.dest_bucket_name: %s",
         cloud_env_options.dest_bucket.GetBucketName().c_str());
  Header(info_log_, "     AwsEnv.dest_object_path: %s",
         cloud_env_options.dest_bucket.GetObjectPath().c_str());
  Header(info_log_, "     AwsEnv.dest_bucket_region: %s",
         cloud_env_options.dest_bucket.GetRegion().c_str());
  Header(info_log_, "            AwsEnv.credentials: %s",
         creds ? "[given]" : "[not given]");

  base_env_ = underlying_env;

  // These lines of code are likely temporary until the new configuration stuff
  // comes into play.
  create_bucket_status_ =
      CloudStorageProvider::LoadStorageProvider(this, "s3", &storage_provider_);
  // create cloud log client for storing/reading logs
  if (create_bucket_status_.ok() && !cloud_env_options.keep_local_log_files) {
    if (cloud_env_options.log_type == kLogKinesis) {
      create_bucket_status_ =
          CreateKinesisController(this, &cloud_log_controller_);
    } else if (cloud_env_options.log_type == kLogKafka) {
#ifdef USE_KAFKA
      create_bucket_status_ =
          CreateKafkaController(this, &cloud_log_controller_);
#else
      create_bucket_status_ = Status::NotSupported(
          "In order to use Kafka, make sure you're compiling with "
          "USE_KAFKA=1");

      Log(InfoLogLevel::ERROR_LEVEL, info_log,
          "[aws] NewAwsEnv Unknown log type %d. %s",
          cloud_env_options.log_type,
          create_bucket_status_.ToString().c_str());
#endif /* USE_KAFKA */
    } else {
      create_bucket_status_ =
          Status::NotSupported("We currently only support Kinesis and Kafka");

      Log(InfoLogLevel::ERROR_LEVEL, info_log,
          "[aws] NewAwsEnv Unknown log type %d. %s", cloud_env_options.log_type,
          create_bucket_status_.ToString().c_str());
    }
  }
  if (!create_bucket_status_.ok()) {
    Log(InfoLogLevel::ERROR_LEVEL, info_log,
        "[aws] NewAwsEnv Unable to create environment %s",
        create_bucket_status_.ToString().c_str());
  }
}

AwsEnv::~AwsEnv() {
}

Status AwsEnv::SanitizeOptions() {
  if (create_bucket_status_.ok()) {
    create_bucket_status_ = CloudEnvImpl::SanitizeOptions();
  }
  return create_bucket_status_;
}

Status AwsEnv::status() { return create_bucket_status_; }

//
// Check if options are compatible with the S3 storage system
//
Status AwsEnv::CheckOption(const EnvOptions& options) {
  // Cannot mmap files that reside on AWS S3, unless the file is also local
  if (options.use_mmap_reads && !cloud_env_options.keep_local_sst_files) {
    std::string msg = "Mmap only if keep_local_sst_files is set";
    return Status::InvalidArgument(msg);
  }
  return Status::OK();
}

// Ability to read a file directly from cloud storage
Status AwsEnv::NewSequentialFileCloud(const std::string& bucket,
                                      const std::string& fname,
                                      unique_ptr<SequentialFile>* result,
                                      const EnvOptions& options) {
  assert(status().ok());
  unique_ptr<CloudStorageReadableFile> file;
  Status st = storage_provider_->NewCloudReadableFile(bucket, fname, &file);
  if (!st.ok()) {
    return st;
  }

  result->reset(dynamic_cast<SequentialFile*>(file.release()));
  return st;
}

// open a file for sequential reading
Status AwsEnv::NewSequentialFile(const std::string& logical_fname,
                                 unique_ptr<SequentialFile>* result,
                                 const EnvOptions& options) {
  assert(status().ok());
  result->reset();

  auto fname = RemapFilename(logical_fname);
  auto file_type = GetFileType(fname);
  bool sstfile = (file_type == RocksDBFileType::kSstFile),
       manifest = (file_type == RocksDBFileType::kManifestFile),
       identity = (file_type == RocksDBFileType::kIdentityFile),
       logfile = (file_type == RocksDBFileType::kLogFile);

  auto st = CheckOption(options);
  if (!st.ok()) {
    return st;
  }

  if (sstfile || manifest || identity) {
    // We read first from local storage and then from cloud storage.
    st = base_env_->NewSequentialFile(fname, result, options);

    if (!st.ok()) {
      if (cloud_env_options.keep_local_sst_files || !sstfile) {
        // copy the file to the local storage if keep_local_sst_files is true
        if (HasDestBucket()) {
          st = storage_provider_->GetObject(GetDestBucketName(),
                                            destname(fname), fname);
        }
        if (!st.ok() && HasSrcBucket() && !SrcMatchesDest()) {
          st = storage_provider_->GetObject(GetSrcBucketName(), srcname(fname),
                                            fname);
        }
        if (st.ok()) {
          // we successfully copied the file, try opening it locally now
          st = base_env_->NewSequentialFile(fname, result, options);
        }
      } else {
        unique_ptr<CloudStorageReadableFile> file;
        if (!st.ok() && HasDestBucket()) {  // read from destination S3
          st = storage_provider_->NewCloudReadableFile(GetDestBucketName(),
                                                       destname(fname), &file);
        }
        if (!st.ok() && HasSrcBucket()) {  // read from src bucket
          st = storage_provider_->NewCloudReadableFile(GetSrcBucketName(),
                                                       srcname(fname), &file);
        }
        if (st.ok()) {
          result->reset(dynamic_cast<SequentialFile*>(file.release()));
        }
      }
    }
    Log(InfoLogLevel::DEBUG_LEVEL, info_log_,
        "[aws] NewSequentialFile file %s %s", fname.c_str(),
        st.ToString().c_str());
    return st;

  } else if (logfile && !cloud_env_options.keep_local_log_files) {
    // read from Kinesis
    st = cloud_log_controller_->status();
    if (st.ok()) {
      // map  pathname to cache dir
      std::string pathname = cloud_log_controller_->GetCachePath(Slice(fname));
      Log(InfoLogLevel::DEBUG_LEVEL, info_log_,
          "[Kinesis] NewSequentialFile logfile %s %s", pathname.c_str(), "ok");

      auto lambda = [this, pathname, &result, options]() -> Status {
        return base_env_->NewSequentialFile(pathname, result, options);
      };
      return cloud_log_controller_->Retry(lambda);
    }
  }

  // This is neither a sst file or a log file. Read from default env.
  return base_env_->NewSequentialFile(fname, result, options);
}

// open a file for random reading
Status AwsEnv::NewRandomAccessFile(const std::string& logical_fname,
                                   unique_ptr<RandomAccessFile>* result,
                                   const EnvOptions& options) {
  assert(status().ok());
  result->reset();

  auto fname = RemapFilename(logical_fname);
  auto file_type = GetFileType(fname);
  bool sstfile = (file_type == RocksDBFileType::kSstFile),
       manifest = (file_type == RocksDBFileType::kManifestFile),
       identity = (file_type == RocksDBFileType::kIdentityFile),
       logfile = (file_type == RocksDBFileType::kLogFile);

  // Validate options
  auto st = CheckOption(options);
  if (!st.ok()) {
    return st;
  }

  if (sstfile || manifest || identity) {
    // Read from local storage and then from cloud storage.
    st = base_env_->NewRandomAccessFile(fname, result, options);

    if (!st.ok() && !base_env_->FileExists(fname).IsNotFound()) {
      // if status is not OK, but file does exist locally, something is wrong
      return st;
    }

    if (cloud_env_options.keep_local_sst_files || !sstfile) {
      if (!st.ok()) {
        // copy the file to the local storage if keep_local_sst_files is true
        if (HasDestBucket()) {
          st = storage_provider_->GetObject(GetDestBucketName(),
                                            destname(fname), fname);
        }
        if (!st.ok() && HasSrcBucket() && !SrcMatchesDest()) {
          st = storage_provider_->GetObject(GetSrcBucketName(), srcname(fname),
                                            fname);
        }
        if (st.ok()) {
          // we successfully copied the file, try opening it locally now
          st = base_env_->NewRandomAccessFile(fname, result, options);
        }
      }
      // If we are being paranoic, then we validate that our file size is
      // the same as in cloud storage.
      if (st.ok() && sstfile && cloud_env_options.validate_filesize) {
        uint64_t remote_size = 0;
        uint64_t local_size = 0;
        Status stax = base_env_->GetFileSize(fname, &local_size);
        if (!stax.ok()) {
          return stax;
        }
        stax = Status::NotFound();
        if (HasDestBucket()) {
          storage_provider_->GetObjectSize(GetDestBucketName(), destname(fname),
                                           &remote_size);
        }
        if (stax.IsNotFound() && HasSrcBucket()) {
          stax = storage_provider_->GetObjectSize(GetSrcBucketName(),
                                                  srcname(fname), &remote_size);
        }
        if (stax.IsNotFound() && !HasDestBucket()) {
          // It is legal for file to not be present in S3 if destination bucket
          // is not set.
        } else if (!stax.ok() || remote_size != local_size) {
          std::string msg = "[aws] HeadObject src " + fname + " local size " +
                            std::to_string(local_size) + " cloud size " +
                            std::to_string(remote_size) + " " + stax.ToString();
          Log(InfoLogLevel::ERROR_LEVEL, info_log_, "%s", msg.c_str());
          return Status::IOError(msg);
        }
      }
    } else if (!st.ok()) {
      // Only execute this code path if keep_local_sst_files == false. If it's
      // true, we will never use S3ReadableFile to read; we copy the file
      // locally and read using base_env.
      unique_ptr<CloudStorageReadableFile> file;
      if (!st.ok() && HasDestBucket()) {
        st = storage_provider_->NewCloudReadableFile(GetDestBucketName(),
                                                     destname(fname), &file);
      }
      if (!st.ok() && HasSrcBucket()) {
        st = storage_provider_->NewCloudReadableFile(GetSrcBucketName(),
                                                     srcname(fname), &file);
      }
      if (st.ok()) {
        result->reset(dynamic_cast<RandomAccessFile*>(file.release()));
      }
    }
    Log(InfoLogLevel::DEBUG_LEVEL, info_log_,
        "[aws] NewRandomAccessFile file %s %s", fname.c_str(),
        st.ToString().c_str());
    return st;

  } else if (logfile && !cloud_env_options.keep_local_log_files) {
    // read from Kinesis
    st = cloud_log_controller_->status();
    if (st.ok()) {
      // map  pathname to cache dir
      std::string pathname = cloud_log_controller_->GetCachePath(Slice(fname));
      Log(InfoLogLevel::DEBUG_LEVEL, info_log_,
          "[kinesis] NewRandomAccessFile logfile %s %s", pathname.c_str(),
          "ok");

      auto lambda = [this, pathname, &result, options]() -> Status {
        return base_env_->NewRandomAccessFile(pathname, result, options);
      };
      return cloud_log_controller_->Retry(lambda);
    }
  }

  // This is neither a sst file or a log file. Read from default env.
  return base_env_->NewRandomAccessFile(fname, result, options);
}

// create a new file for writing
Status AwsEnv::NewWritableFile(const std::string& logical_fname,
                               unique_ptr<WritableFile>* result,
                               const EnvOptions& options) {
  assert(status().ok());
  result->reset();

  auto fname = RemapFilename(logical_fname);
  auto file_type = GetFileType(fname);
  bool sstfile = (file_type == RocksDBFileType::kSstFile),
       manifest = (file_type == RocksDBFileType::kManifestFile),
       identity = (file_type == RocksDBFileType::kIdentityFile),
       logfile = (file_type == RocksDBFileType::kLogFile);

  Status s;

  if (HasDestBucket() && (sstfile || identity || manifest)) {
    std::unique_ptr<CloudStorageWritableFile> f;
    storage_provider_->NewCloudWritableFile(fname, GetDestBucketName(),
                                            destname(fname), &f, options);
    s = f->status();
    if (!s.ok()) {
      Log(InfoLogLevel::ERROR_LEVEL, info_log_,
          "[aws] NewWritableFile src %s %s", fname.c_str(),
          s.ToString().c_str());
      return s;
    }
    result->reset(dynamic_cast<WritableFile*>(f.release()));
  } else if (logfile && !cloud_env_options.keep_local_log_files) {
    std::unique_ptr<CloudLogWritableFile> f(
        cloud_log_controller_->CreateWritableFile(fname, options));
    if (!f || !f->status().ok()) {
      s = Status::IOError("[aws] NewWritableFile", fname.c_str());
      Log(InfoLogLevel::ERROR_LEVEL, info_log_,
          "[kinesis] NewWritableFile src %s %s", fname.c_str(),
          s.ToString().c_str());
      return s;
    }
    result->reset(dynamic_cast<WritableFile*>(f.release()));
  } else {
    s = base_env_->NewWritableFile(fname, result, options);
  }
  Log(InfoLogLevel::DEBUG_LEVEL, info_log_, "[aws] NewWritableFile src %s %s",
      fname.c_str(), s.ToString().c_str());
  return s;
}

class S3Directory : public Directory {
 public:
  explicit S3Directory(AwsEnv* env, const std::string name)
      : env_(env), name_(name) {
    status_ = env_->GetBaseEnv()->NewDirectory(name, &posixDir);
  }

  ~S3Directory() {}

  virtual Status Fsync() {
    if (!status_.ok()) {
      return status_;
    }
    return posixDir->Fsync();
  }

  virtual Status status() { return status_; }

 private:
  AwsEnv* env_;
  std::string name_;
  Status status_;
  unique_ptr<Directory> posixDir;
};

//
//  Returns success only if the directory-bucket exists in the
//  AWS S3 service and the posixEnv local directory exists as well.
//
Status AwsEnv::NewDirectory(const std::string& name,
                            unique_ptr<Directory>* result) {
  assert(status().ok());
  result->reset(nullptr);

  Log(InfoLogLevel::DEBUG_LEVEL, info_log_, "[aws] NewDirectory name '%s'",
      name.c_str());

  // create new object.
  unique_ptr<S3Directory> d(new S3Directory(this, name));

  // Check if the path exists in local dir
  if (!d->status().ok()) {
    Log(InfoLogLevel::ERROR_LEVEL, info_log_,
        "[aws] NewDirectory name %s unable to create local dir", name.c_str());
    return d->status();
  }
  result->reset(d.release());
  Log(InfoLogLevel::DEBUG_LEVEL, info_log_, "[aws] NewDirectory name %s ok",
      name.c_str());
  return Status::OK();
}

//
// Check if the specified filename exists.
//
Status AwsEnv::FileExists(const std::string& logical_fname) {
  assert(status().ok());
  Status st;

  auto fname = RemapFilename(logical_fname);
  auto file_type = GetFileType(fname);
  bool sstfile = (file_type == RocksDBFileType::kSstFile),
       manifest = (file_type == RocksDBFileType::kManifestFile),
       identity = (file_type == RocksDBFileType::kIdentityFile),
       logfile = (file_type == RocksDBFileType::kLogFile);

  if (sstfile || manifest || identity) {
    // We read first from local storage and then from cloud storage.
    st = base_env_->FileExists(fname);
    if (st.IsNotFound() && HasDestBucket()) {
      st =
          storage_provider_->ExistsObject(GetDestBucketName(), destname(fname));
    }
    if (!st.ok() && HasSrcBucket()) {
      st = storage_provider_->ExistsObject(GetSrcBucketName(), srcname(fname));
    }
  } else if (logfile && !cloud_env_options.keep_local_log_files) {
    // read from Kinesis
    st = cloud_log_controller_->status();
    if (st.ok()) {
      // map  pathname to cache dir
      std::string pathname = cloud_log_controller_->GetCachePath(Slice(fname));
      Log(InfoLogLevel::DEBUG_LEVEL, info_log_,
          "[kinesis] FileExists logfile %s %s", pathname.c_str(), "ok");

      auto lambda = [this, pathname]() -> Status {
        return base_env_->FileExists(pathname);
      };
      st = cloud_log_controller_->Retry(lambda);
    }
  } else {
    st = base_env_->FileExists(fname);
  }
  Log(InfoLogLevel::DEBUG_LEVEL, info_log_, "[aws] FileExists path '%s' %s",
      fname.c_str(), st.ToString().c_str());
  return st;
}


Status AwsEnv::GetChildren(const std::string& path,
                           std::vector<std::string>* result) {
  assert(status().ok());
  Log(InfoLogLevel::DEBUG_LEVEL, info_log_, "[aws] GetChildren path '%s' ",
      path.c_str());
  result->clear();

  // Fetch the list of children from both buckets in S3
  Status st;
  if (HasSrcBucket()) {
    st = storage_provider_->ListObjects(GetSrcBucketName(), GetSrcObjectPath(),
                                        result);
    if (!st.ok()) {
      Log(InfoLogLevel::ERROR_LEVEL, info_log_,
          "[aws] GetChildren src bucket %s %s error from S3 %s",
          GetSrcBucketName().c_str(), path.c_str(), st.ToString().c_str());
      return st;
    }
  }
  if (HasDestBucket() && !SrcMatchesDest()) {
    std::vector<std::string> dest_objects;
    st = storage_provider_->ListObjects(GetDestBucketName(),
                                        GetDestObjectPath(), &dest_objects);
    if (!st.ok()) {
      Log(InfoLogLevel::ERROR_LEVEL, info_log_,
          "[aws] GetChildren dest bucket %s %s error from S3 %s",
          GetDestBucketName().c_str(), path.c_str(), st.ToString().c_str());
      return st;
    }
    for (auto const& value : dest_objects) {
      result->push_back(value);
    }
  }
  // fetch all files that exist in the local posix directory
  std::vector<std::string> local_files;
  st = base_env_->GetChildren(path, &local_files);
  if (!st.ok()) {
    Log(InfoLogLevel::ERROR_LEVEL, info_log_,
        "[aws] GetChildren %s error on local dir", path.c_str());
    return st;
  }

  for (auto const& value : local_files) {
    result->push_back(value);
  }

  // Remove all results that are not supposed to be visible.
  result->erase(
      std::remove_if(result->begin(), result->end(),
                     [&](const std::string& f) {
                       auto noepoch = RemoveEpoch(f);
                       if (!IsSstFile(noepoch) && !IsManifestFile(noepoch)) {
                         return false;
                       }
                       return RemapFilename(noepoch) != f;
                     }),
      result->end());
  // Remove the epoch, remap into RocksDB's domain
  for (size_t i = 0; i < result->size(); ++i) {
    auto noepoch = RemoveEpoch(result->at(i));
    if (IsSstFile(noepoch) || IsManifestFile(noepoch)) {
      // remap sst and manifest files
      result->at(i) = noepoch;
    }
  }
  // remove duplicates
  std::sort(result->begin(), result->end());
  result->erase(std::unique(result->begin(), result->end()), result->end());

  Log(InfoLogLevel::DEBUG_LEVEL, info_log_,
      "[aws] GetChildren %s successfully returned %d files", path.c_str(),
      result->size());
  return Status::OK();
}

Status AwsEnv::DeleteFile(const std::string& logical_fname) {
  assert(status().ok());

  auto fname = RemapFilename(logical_fname);
  auto file_type = GetFileType(fname);
  bool sstfile = (file_type == RocksDBFileType::kSstFile),
       manifest = (file_type == RocksDBFileType::kManifestFile),
       identity = (file_type == RocksDBFileType::kIdentityFile),
       logfile = (file_type == RocksDBFileType::kLogFile);

  if (manifest) {
    // We don't delete manifest files. The reason for this is that even though
    // RocksDB creates manifest with different names (like MANIFEST-00001,
    // MANIFEST-00008) we actually map all of them to the same filename
    // MANIFEST-[epoch].
    // When RocksDB wants to roll the MANIFEST (let's say from 1 to 8) it does
    // the following:
    // 1. Create a new MANIFEST-8
    // 2. Write everything into MANIFEST-8
    // 3. Sync MANIFEST-8
    // 4. Store "MANIFEST-8" in CURRENT file
    // 5. Delete MANIFEST-1
    //
    // What RocksDB cloud does behind the scenes (the numbers match the list
    // above):
    // 1. Create manifest file MANIFEST-[epoch].tmp
    // 2. Forward RocksDB writes to the file created in the first step
    // 3. Atomic rename from MANIFEST-[epoch].tmp to MANIFEST-[epoch]. The old
    // file with the same file name is overwritten.
    // 4. Nothing. Whatever the contents of CURRENT file, we don't care, we
    // always remap MANIFEST files to the correct with the latest epoch.
    // 5. Also nothing. There is no file to delete, because we have overwritten
    // it in the third step.
    return Status::OK();
  }

  Status st;
  // Delete from destination bucket and local dir
  if (sstfile || manifest || identity) {
    if (HasDestBucket()) {
      // add the remote file deletion to the queue
      st = DeleteCloudFileFromDest(basename(fname));
    }
    // delete from local, too. Ignore the result, though. The file might not be
    // there locally.
    base_env_->DeleteFile(fname);
  } else if (logfile && !cloud_env_options.keep_local_log_files) {
    // read from Kinesis
    st = cloud_log_controller_->status();
    if (st.ok()) {
      // Log a Delete record to kinesis stream
      std::unique_ptr<CloudLogWritableFile> f(
          cloud_log_controller_->CreateWritableFile(fname, EnvOptions()));
      if (!f || !f->status().ok()) {
        st = Status::IOError("[Kinesis] DeleteFile", fname.c_str());
      } else {
        st = f->LogDelete();
      }
    }
  } else {
    st = base_env_->DeleteFile(fname);
  }
  Log(InfoLogLevel::DEBUG_LEVEL, info_log_, "[aws] DeleteFile file %s %s",
      fname.c_str(), st.ToString().c_str());
  return st;
}

// S3 has no concepts of directories, so we just have to forward the request to
// base_env_
Status AwsEnv::CreateDir(const std::string& dirname) {
  assert(status().ok());
  Log(InfoLogLevel::DEBUG_LEVEL, info_log_, "[aws] CreateDir dir '%s'",
      dirname.c_str());
  Status st;

  // create local dir
  st = base_env_->CreateDir(dirname);

  Log(InfoLogLevel::DEBUG_LEVEL, info_log_, "[aws] CreateDir dir %s %s",
      dirname.c_str(), st.ToString().c_str());
  return st;
};

// S3 has no concepts of directories, so we just have to forward the request to
// base_env_
Status AwsEnv::CreateDirIfMissing(const std::string& dirname) {
  assert(status().ok());
  Log(InfoLogLevel::DEBUG_LEVEL, info_log_, "[aws] CreateDirIfMissing dir '%s'",
      dirname.c_str());
  Status st;

  // create directory in base_env_
  st = base_env_->CreateDirIfMissing(dirname);

  Log(InfoLogLevel::DEBUG_LEVEL, info_log_,
      "[aws] CreateDirIfMissing created dir %s %s", dirname.c_str(),
      st.ToString().c_str());
  return st;
};

// S3 has no concepts of directories, so we just have to forward the request to
// base_env_
Status AwsEnv::DeleteDir(const std::string& dirname) {
  assert(status().ok());
  Log(InfoLogLevel::DEBUG_LEVEL, info_log_, "[aws] DeleteDir src '%s'",
      dirname.c_str());
  Status st = base_env_->DeleteDir(dirname);
  Log(InfoLogLevel::DEBUG_LEVEL, info_log_, "[aws] DeleteDir dir %s %s",
      dirname.c_str(), st.ToString().c_str());
  return st;
};

Status AwsEnv::GetFileSize(const std::string& logical_fname, uint64_t* size) {
  assert(status().ok());
  *size = 0L;

  auto fname = RemapFilename(logical_fname);
  auto file_type = GetFileType(fname);
  bool sstfile = (file_type == RocksDBFileType::kSstFile),
       logfile = (file_type == RocksDBFileType::kLogFile);

  Status st;
  if (sstfile) {
    if (base_env_->FileExists(fname).ok()) {
      st = base_env_->GetFileSize(fname, size);
    } else {
      st = Status::NotFound();
      // Get file length from S3
      if (HasDestBucket()) {
        st = storage_provider_->GetObjectSize(GetDestBucketName(),
                                              destname(fname), size);
      }
      if (st.IsNotFound() && HasSrcBucket()) {
        st = storage_provider_->GetObjectSize(GetSrcBucketName(),
                                              srcname(fname), size);
      }
    }
  } else if (logfile && !cloud_env_options.keep_local_log_files) {
    st = cloud_log_controller_->status();
    if (st.ok()) {
      // map  pathname to cache dir
      std::string pathname = cloud_log_controller_->GetCachePath(Slice(fname));
      Log(InfoLogLevel::DEBUG_LEVEL, info_log_,
          "[kinesis] GetFileSize logfile %s %s", pathname.c_str(), "ok");

      auto lambda = [this, pathname, size]() -> Status {
        return base_env_->GetFileSize(pathname, size);
      };
      st = cloud_log_controller_->Retry(lambda);
    }
  } else {
    st = base_env_->GetFileSize(fname, size);
  }
  Log(InfoLogLevel::DEBUG_LEVEL, info_log_, "[aws] GetFileSize src '%s' %s %ld",
      fname.c_str(), st.ToString().c_str(), *size);
  return st;
}

Status AwsEnv::GetFileModificationTime(const std::string& logical_fname,
                                       uint64_t* time) {
  assert(status().ok());
  *time = 0;

  auto fname = RemapFilename(logical_fname);
  auto file_type = GetFileType(fname);
  bool sstfile = (file_type == RocksDBFileType::kSstFile),
       logfile = (file_type == RocksDBFileType::kLogFile);

  Status st;
  if (sstfile) {
    if (base_env_->FileExists(fname).ok()) {
      st = base_env_->GetFileModificationTime(fname, time);
    } else {
      st = Status::NotFound();
      if (HasDestBucket()) {
        st = storage_provider_->GetObjectModificationTime(
            GetDestBucketName(), destname(fname), time);
      }
      if (st.IsNotFound() && HasSrcBucket()) {
        st = storage_provider_->GetObjectModificationTime(GetSrcBucketName(),
                                                          srcname(fname), time);
      }
    }
  } else if (logfile && !cloud_env_options.keep_local_log_files) {
    st = cloud_log_controller_->status();
    if (st.ok()) {
      // map  pathname to cache dir
      std::string pathname = cloud_log_controller_->GetCachePath(Slice(fname));
      Log(InfoLogLevel::DEBUG_LEVEL, info_log_,
          "[kinesis] GetFileModificationTime logfile %s %s", pathname.c_str(),
          "ok");

      auto lambda = [this, pathname, time]() -> Status {
        return base_env_->GetFileModificationTime(pathname, time);
      };
      st = cloud_log_controller_->Retry(lambda);
    }
  } else {
    st = base_env_->GetFileModificationTime(fname, time);
  }
  Log(InfoLogLevel::DEBUG_LEVEL, info_log_,
      "[aws] GetFileModificationTime src '%s' %s", fname.c_str(),
      st.ToString().c_str());
  return st;
}

// The rename is not atomic. S3 does not support renaming natively.
// Copy file to a new object in S3 and then delete original object.
Status AwsEnv::RenameFile(const std::string& logical_src,
                          const std::string& logical_target) {
  assert(status().ok());

  auto src = RemapFilename(logical_src);
  auto target = RemapFilename(logical_target);
  // Get file type of target
  auto file_type = GetFileType(target);
  bool sstfile = (file_type == RocksDBFileType::kSstFile),
       manifest = (file_type == RocksDBFileType::kManifestFile),
       identity = (file_type == RocksDBFileType::kIdentityFile),
       logfile = (file_type == RocksDBFileType::kLogFile);

  // Rename should never be called on sst files.
  if (sstfile) {
    Log(InfoLogLevel::DEBUG_LEVEL, info_log_,
        "[aws] RenameFile source sstfile %s %s is not supported", src.c_str(),
        target.c_str());
    assert(0);
    return Status::NotSupported(Slice(src), Slice(target));
  } else if (logfile) {
    // Rename should never be called on log files as well
    Log(InfoLogLevel::ERROR_LEVEL, info_log_,
        "[aws] RenameFile source logfile %s %s is not supported", src.c_str(),
        target.c_str());
    assert(0);
    return Status::NotSupported(Slice(src), Slice(target));
  } else if (manifest) {
    // Rename should never be called on manifest files as well
    Log(InfoLogLevel::ERROR_LEVEL, info_log_,
        "[aws] RenameFile source manifest %s %s is not supported", src.c_str(),
        target.c_str());
    assert(0);
    return Status::NotSupported(Slice(src), Slice(target));

  } else if (!identity || !HasDestBucket()) {
    return base_env_->RenameFile(src, target);
  }
  // Only ID file should come here
  assert(identity);
  assert(HasDestBucket());
  assert(basename(target) == "IDENTITY");

  // Save Identity to S3
  Status st = SaveIdentitytoS3(src, destname(target));

  // Do the rename on local filesystem too
  if (st.ok()) {
    st = base_env_->RenameFile(src, target);
  }
  Log(InfoLogLevel::DEBUG_LEVEL, info_log_,
      "[aws] RenameFile src %s target %s: %s", src.c_str(), target.c_str(),
      st.ToString().c_str());
  return st;
}

Status AwsEnv::LinkFile(const std::string& src, const std::string& target) {
  // We only know how to link file if both src and dest buckets are empty
  if (HasDestBucket() || HasSrcBucket()) {
    return Status::NotSupported();
  }
  auto src_remapped = RemapFilename(src);
  auto target_remapped = RemapFilename(target);
  return base_env_->LinkFile(src_remapped, target_remapped);
}

//
// Copy my IDENTITY file to cloud storage. Update dbid registry.
//
Status AwsEnv::SaveIdentitytoS3(const std::string& localfile,
                                const std::string& idfile) {
  assert(basename(idfile) == "IDENTITY");

  // Read id into string
  std::string dbid;
  Status st = ReadFileToString(base_env_, localfile, &dbid);
  dbid = trim(dbid);

  // Upload ID file to  S3
  if (st.ok()) {
    st = storage_provider_->PutObject(localfile, GetDestBucketName(), idfile);
  }

  // Save mapping from ID to cloud pathname
  if (st.ok() && !GetDestObjectPath().empty()) {
    st = SaveDbid(GetDestBucketName(), dbid, GetDestObjectPath());
  }
  return st;
}

//
// All db in a bucket are stored in path /.rockset/dbid/<dbid>
// The value of the object is the pathname where the db resides.
//
Status AwsEnv::SaveDbid(const std::string& bucket_name, const std::string& dbid,
                        const std::string& dirname) {
  assert(status().ok());
  Log(InfoLogLevel::DEBUG_LEVEL, info_log_, "[aws] SaveDbid dbid %s dir '%s'",
      dbid.c_str(), dirname.c_str());

  std::string dbidkey = dbid_registry_ + dbid;
  std::unordered_map<std::string, std::string> metadata;
  metadata["dirname"] = dirname;

  Status st =
      storage_provider_->PutObjectMetadata(bucket_name, dbidkey, metadata);
  if (!st.ok()) {
    Log(InfoLogLevel::ERROR_LEVEL, info_log_,
        "[aws] Bucket %s SaveDbid error in saving dbid %s dirname %s %s",
        bucket_name.c_str(), dbid.c_str(), dirname.c_str(),
        st.ToString().c_str());
  } else {
    Log(InfoLogLevel::INFO_LEVEL, info_log_,
        "[aws] Bucket %s SaveDbid dbid %s dirname %s %s", bucket_name.c_str(),
        dbid.c_str(), dirname.c_str(), "ok");
  }
  return st;
};

//
// Given a dbid, retrieves its pathname.
//
Status AwsEnv::GetPathForDbid(const std::string& bucket,
                              const std::string& dbid, std::string* dirname) {
  std::string dbidkey = dbid_registry_ + dbid;

  Log(InfoLogLevel::DEBUG_LEVEL, info_log_,
      "[aws] Bucket %s GetPathForDbid dbid %s", bucket.c_str(), dbid.c_str());

  std::unordered_map<std::string, std::string> metadata;
  Status st = storage_provider_->GetObjectMetadata(bucket, dbidkey, &metadata);
  if (!st.ok()) {
    if (st.IsNotFound()) {
      Log(InfoLogLevel::ERROR_LEVEL, info_log_,
          "[aws] %s GetPathForDbid error non-existent dbid %s %s",
          bucket.c_str(), dbid.c_str(), st.ToString().c_str());
    } else {
      Log(InfoLogLevel::ERROR_LEVEL, info_log_,
          "[aws] %s GetPathForDbid error dbid %s %s", bucket.c_str(),
          dbid.c_str(), st.ToString().c_str());
    }
    return st;
  }

  // Find "dirname" metadata that stores the pathname of the db
  const char* kDirnameTag = "dirname";
  auto it = metadata.find(kDirnameTag);
  if (it != metadata.end()) {
    *dirname = it->second;
  } else {
    st = Status::NotFound("GetPathForDbid");
  }
  Log(InfoLogLevel::INFO_LEVEL, info_log_, "[aws] %s GetPathForDbid dbid %s %s",
      bucket.c_str(), dbid.c_str(), st.ToString().c_str());
  return st;
}

//
// Retrieves the list of all registered dbids and their paths
//
Status AwsEnv::GetDbidList(const std::string& bucket, DbidList* dblist) {

  // fetch the list all all dbids
  std::vector<std::string> dbid_list;
  Status st =
      storage_provider_->ListObjects(bucket, dbid_registry_, &dbid_list);
  if (!st.ok()) {
    Log(InfoLogLevel::ERROR_LEVEL, info_log_,
        "[aws] %s GetDbidList error in GetChildrenFromS3 %s", bucket.c_str(),
        st.ToString().c_str());
    return st;
  }
  // for each dbid, fetch the db directory where the db data should reside
  for (auto dbid : dbid_list) {
    std::string dirname;
    st = GetPathForDbid(bucket, dbid, &dirname);
    if (!st.ok()) {
      Log(InfoLogLevel::ERROR_LEVEL, info_log_,
          "[aws] %s GetDbidList error in GetPathForDbid(%s) %s", bucket.c_str(),
          dbid.c_str(), st.ToString().c_str());
      return st;
    }
    // insert item into result set
    (*dblist)[dbid] = dirname;
  }
  return st;
}

//
// Deletes the specified dbid from the registry
//
Status AwsEnv::DeleteDbid(const std::string& bucket,
                          const std::string& dbid) {

  // fetch the list all all dbids
  std::string dbidkey = dbid_registry_ + dbid;
  Status st = storage_provider_->DeleteObject(bucket, dbidkey);
  Log(InfoLogLevel::DEBUG_LEVEL, info_log_,
      "[aws] %s DeleteDbid DeleteDbid(%s) %s", bucket.c_str(), dbid.c_str(),
      st.ToString().c_str());
  return st;
}

//
// prepends the configured src object path name
//
std::string AwsEnv::srcname(const std::string& localname) {
  assert(cloud_env_options.src_bucket.IsValid());
  return cloud_env_options.src_bucket.GetObjectPath() + "/" + basename(localname);
}

//
// prepends the configured dest object path name
//
std::string AwsEnv::destname(const std::string& localname) {
  assert(cloud_env_options.dest_bucket.IsValid());
  return cloud_env_options.dest_bucket.GetObjectPath() + "/" + basename(localname);
}

Status AwsEnv::LockFile(const std::string& fname, FileLock** lock) {
  // there isn's a very good way to atomically check and create
  // a file via libs3
  *lock = nullptr;
  return Status::OK();
}

Status AwsEnv::UnlockFile(FileLock* lock) { return Status::OK(); }

Status AwsEnv::NewLogger(const std::string& fname, shared_ptr<Logger>* result) {
  return base_env_->NewLogger(fname, result);
}

// The factory method for creating an S3 Env
Status AwsEnv::NewAwsEnv(Env* base_env,
                         const CloudEnvOptions& cloud_options,
                         const std::shared_ptr<Logger> & info_log, CloudEnv** cenv) {
  Status status;
  *cenv = nullptr;
  // If underlying env is not defined, then use PosixEnv
  if (!base_env) {
    base_env = Env::Default();
  }
  unique_ptr<AwsEnv> aenv(new AwsEnv(base_env, cloud_options, info_log));
  status = aenv->SanitizeOptions();
  if (status.ok()) {
    *cenv = aenv.release();
  }
  return status;
}

std::string AwsEnv::GetWALCacheDir() {
  return cloud_log_controller_->GetCacheDir();
}


#pragma GCC diagnostic pop
#endif  // USE_AWS
}  // namespace rocksdb

