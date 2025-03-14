CMAKE_MINIMUM_REQUIRED(VERSION 3.13)
PROJECT(saslauthd-port)

# This file is used by the build process for the complete Couchbase Server

GoModBuild(TARGET saslauthd-port
          PACKAGE github.com/couchbase/cbauth/cmd/saslauthd-port
          GOVERSION SUPPORTED_NEWER
          INSTALL_PATH bin)

GoModTidySetup()
