# WP IP Fail Ban

WordPress plugin to block IP subnets after repeated failed login attempts, similar to ipfailban.

## Features

- Monitors failed WordPress login attempts
- Blocks entire IP subnet after a configurable threshold
- Automatic unblocking after ban duration

## Installation

1. Copy `ip-failban.php` to your `wp-content/plugins/` directory.
2. Activate **IP Fail Ban** from your WordPress admin dashboard.

## Customization

Edit the `ip-failban.php` file to change:
- `$failThreshold` (number of failed attempts before banning)
- `$banTime` (ban duration in seconds)
- `$subnetMask` (subnet mask for grouping IPs)

## License

MIT License

Copyright (c) 2025 Infactionfreddy

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.