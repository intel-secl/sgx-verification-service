# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause

FROM centos:8

COPY out/sqvs /usr/bin/sqvs

COPY dist/linux/trusted_rootca.pem /tmp/trusted_rootca.pem

COPY dist/image/entrypoint.sh /entrypoint.sh

RUN touch /.container-env && chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
