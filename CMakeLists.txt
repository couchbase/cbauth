CMAKE_MINIMUM_REQUIRED(VERSION 2.8)
PROJECT(saslauthd-port)

# This file is used by the build process for the complete Couchbase Server

GoInstall(TARGET saslauthd-port
          PACKAGE github.com/couchbase/cbauth/cmd/saslauthd-port
          GOPATH "${CMAKE_SOURCE_DIR}/goproj" "${GODEPSDIR}"
          GOVERSION 1.19
          INSTALL_PATH bin)
