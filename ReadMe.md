[![Wireshark](https://github.com/Open-Markets-Initiative/Open-Markets-Initiative/blob/main/About/Images/Wireshark.png)](https://www.wireshark.org)

# Omi Wireshark C Dissectors

## Coverage

These dissectors are designed to cover the whole protocol: every message, every field,
every published version. 3 protocols and 22 versions here.

Versions are aggregated into one set of identifiers: one field set and one filter
namespace per protocol, versioned only where the wire differs.

Generated from a model of the specification, and published for preview before they are
merged into released Wireshark.

## Proven Models

**The protocol models these dissectors are generated from are proven by Lean 4.**

Each model also generates a [Lean 4 definition][Lean.Definitions.Repository], one module
per protocol version, with theorems relating every decoder to its encoder.

## Usage

These dissectors are published so that you can **build them into a Wireshark of your own, for your own use**.
Generate them, compile them into a Wireshark you build and run, and read your own captures with them.

They **will** be contributed to the Wireshark project through the Open Markets Initiative.
Publishing them here is not an invitation for anyone else to submit them.

> Only authorized users of the Open Markets Initiative may place this code into the Wireshark build.

That covers submitting it to `wireshark/wireshark`, carrying it in a Wireshark
distribution or package, and shipping it inside any Wireshark binary offered to
others. Those rights are reserved and are not granted by this repository.

A Wireshark you build for yourself is yours to build. Wireshark itself is
GPL-2.0-or-later, and nothing here restricts what you do privately with a build
you make; the reservation is on putting this code into builds handed to others.

[License](License) states this in full and is the text that governs.

## Lua Dissectors

The same protocols are published as Lua scripts: [omi-wireshark-lua][Wireshark.Lua.Repository].

No build: drop one in the Wireshark plugins directory and it works. They are LLM
friendly too, so point a model at one, ask it to hide a field or rename a column,
and reload.

Take those to avoid compiling, these for the speed.

## Support Wireshark

Wireshark is free and open source, maintained under the nonprofit Wireshark Foundation,
which relies on donations to fund development, infrastructure, and education.

If these dissectors are useful to you, please consider supporting the foundation:
[Donate to the Wireshark Foundation](https://wiresharkfoundation.org/donate/ "Wireshark Foundation Donations")

## Open Markets Initiative

[![Omi](https://github.com/Open-Markets-Initiative/Open-Markets-Initiative/blob/main/About/Images/Logo.png)](https://github.com/Open-Markets-Initiative/Open-Markets-Initiative)  The Open Markets Initiative (Omi) is a group of technologists
dedicated to enhancing the stability of electronic financial markets using modern
development methods.

Other generated code can be found at [Omi Projects][Omi.Projects]; for Omi rules and
regulations, see [Omi Directory][Omi.Directory].

Useful? A star helps others find [OMI](https://github.com/Open-Markets-Initiative "Open Markets Initiative").

[Omi.Directory]: https://github.com/Open-Markets-Initiative/Open-Markets-Initiative "Open Markets Initiative"
[Omi.Glossary]: https://github.com/Open-Markets-Initiative/Open-Markets-Initiative/tree/main/About "Omi Glossary"
[Omi.Projects]: https://github.com/Open-Markets-Initiative/Open-Markets-Initiative/tree/main/Projects "Open Markets Initiative Projects"
[Wireshark.Lua.Repository]: https://github.com/Open-Markets-Initiative/omi-wireshark-lua "Omi Lua Wireshark Dissectors"
[Lean.Definitions.Repository]: https://github.com/Open-Markets-Initiative/omi-lean-definitions "Omi Lean Definitions"
