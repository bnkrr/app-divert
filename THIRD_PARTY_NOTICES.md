# Third-party notices

The MIT license in LICENSE covers app-divert's own code. Third-party components
retain their respective licenses and are not relicensed under MIT.

## WinDivert

app-divert uses WinDivert through its dynamically loaded DLL interface.
The portable package uses the unmodified official WinDivert 2.2.2-A x64 DLL and
driver. WinDivert offers LGPLv3 or GPLv2; this project uses the LGPLv3 option.

The portable package includes the upstream WinDivert-LICENSE.txt and
WinDivert-README.txt, preserving upstream copyright and license notices.
WinDivert-LICENSE.txt contains the LGPLv3 and accompanying GPLv3 license text.
When redistributing those binaries, retain these notices and provide access to
the corresponding WinDivert source under its license:

- [WinDivert v2.2.2 source and build files](https://github.com/basil00/WinDivert/tree/v2.2.2)
- [Download the v2.2.2 source archive](https://github.com/basil00/WinDivert/archive/refs/tags/v2.2.2.tar.gz)
- [Upstream license](https://github.com/basil00/WinDivert/blob/v2.2.2/LICENSE)

For binary downloads, make the corresponding source available alongside the
binary, or provide clear source-download directions next to the binary download
as permitted by the applicable license. Distributors remain responsible for
source availability; modifications require the matching modified source.

The DLL is loaded from the executable directory, or from Options.DLLDir when
embedded. app-divert imposes no restriction on replacing the library with an
interface-compatible modified version or on reverse engineering to debug such
modifications. Windows driver loading requirements still apply.

## Go runtime, standard library, and golang.org/x/sys

The executable incorporates Go runtime/standard-library code and uses
[golang.org/x/sys](https://pkg.go.dev/golang.org/x/sys), licensed under the
following BSD 3-Clause terms. The module version is recorded in go.mod/go.sum.

```text
Copyright 2009 The Go Authors.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

   * Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
   * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the
distribution.
   * Neither the name of Google LLC nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```
