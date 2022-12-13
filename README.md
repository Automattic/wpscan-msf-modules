# WPScan Metasploit modules

These are generic Metasploit modules for helping to develop proof-of-concept
exploits against vulnerabilities in WordPress and WordPress extensions (themes
and plugins.)

We intentionally keep this collection small and generic in the hope that it
will be useful when demonstrating vulnerabilities.

## Usage

Clone the repository, and start `msfconsole` like this:

```
% msfconsole -m <path-to-repo>/modules
```

Alternatively link the `modules` subdirectory to your `${HOME}/.msf4/modules`
directory, and yous hould be all set.

## License

> Copyright (C) 2022  Automattic, Inc
>
> This program is free software; you can redistribute it and/or
> modify it under the terms of the GNU General Public License
> as published by the Free Software Foundation; either version 2
> of the License, or (at your option) any later version.
>
> This program is distributed in the hope that it will be useful,
> but WITHOUT ANY WARRANTY; without even the implied warranty of
> MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
> GNU General Public License for more details.
>
> You should have received a copy of the GNU General Public License
> along with this program.  If not, see <http://www.gnu.org/licenses/>.
