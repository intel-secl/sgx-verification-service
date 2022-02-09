# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause

FROM ubuntu:focal

COPY out/sqvs /usr/bin/sqvs

COPY dist/image/entrypoint.sh /entrypoint.sh

RUN touch /.container-env && chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]

