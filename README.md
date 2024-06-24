# PommeKit
Experimental Python package for various Apple APIs and services.

## Table of Contents
<!-- TOC -->
* [PommeKit](#pommekit)
  * [Table of Contents](#table-of-contents)
  * [Current Supported Services](#current-supported-services)
  * [Copyright Notice](#copyright-notice)
<!-- TOC -->

## Current Supported Services
| Service/API Name                       | Features/Supported Functions                                                                                                 |
|----------------------------------------|------------------------------------------------------------------------------------------------------------------------------|
| Albert                                 | <ul><li>Generate certificate signing request (CSR)</li><li>Provision APNs credentials (push key/push certificate)</li></ul>  |
| Apple Push Notification service (APNs) | <ul><li>Sending/receiving commands</li><li>Hosting a custom APNs courier</li><li>High-level event-based client API</li></ul> |
| Apple Identity Service (IDS)           | <ul><li>User authentication</li><li>Device registration</li><li>Handle querying</li></ul>                                    |
| GrandSlam Authentication (GSA)         | <ul><li>Authentication via GSA</li><li>Limited RFC 5054-compatible SRP implementation</li></ul>                              |
| Anisette                               | <ul><li>Anisette v3 provisioning via external provider</li></ul>                                                             |



## Copyright Notice
```
PommeKit — Python library with various tools for interacting with Apple services and APIs
Copyright (C) 2024  Cypheriel

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
```