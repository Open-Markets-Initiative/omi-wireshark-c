[![Wireshark](https://github.com/Open-Markets-Initiative/Open-Markets-Initiative/blob/main/About/Images/Wireshark.png)](https://www.wireshark.org)

# Omi Wireshark C Dissectors

## Why C

Wireshark's own dissectors are written in C and compiled into `libwireshark`. These are
the same kind of thing. They run inside Wireshark rather than on top of it, and that
changes what they can do.

**Speed.** Nothing interprets a script for every field of every message, so a compiled
dissector holds up on captures large enough to matter: a full session rather than a
sample of one.

**Typed fields.** A timestamp is an absolute time that Wireshark renders as a date, a
price is a scaled number, an enumeration reads as its name. Filters, columns and
statistics treat them as they treat any built-in protocol, because they are the same
field types.

**Expert information.** What is malformed, truncated or unexpected is flagged where
Wireshark surfaces it, and can be filtered on.

**Preferences and heuristics.** Pin a version, change what is shown, or let the
dissector recognise its own traffic without being told which protocol it is.

**No dependency.** There is no plugin directory to populate and no script to reload, and
a Wireshark built without Lua runs them just the same. `tshark` and `sharkd` get exactly
what the graphical Wireshark gets.

## Coverage

Each dissector is the whole protocol, not the part of it somebody needed. Every message
the specification defines, every field of every message, and every version the exchange
has published: 3 protocols and 22 versions here, each protocol read end to end by a
single dissector. A capture from the first version of a feed and a capture from the
current one are dissected by the same file.

That is what generating them buys. Each is compiled from a model of the specification,
so what it covers is what the specification says rather than what a reader had time for.

They are published for preview before they are merged into released Wireshark, and so
that you can build them into a Wireshark of your own.

## Proven

**The protocol models these dissectors are generated from are proven by Lean 4.**

Each model also generates a [Lean 4 definition][Lean.Definitions.Repository]: one module
per protocol version, with theorems relating every decoder to its encoder. Decoding an
encoded message returns the message it started from, and each field's width is what the
specification says. The Lean toolchain checks every proof on each change.

The model is the one source the C is generated from, so the layout these dissectors read
is proved rather than asserted.

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

The same protocols are published as Lua scripts: [Omi Lua Wireshark Dissectors][Wireshark.Lua.Repository].

Those need no build at all. Drop one in the Wireshark plugins directory and it works,
in a Wireshark you already have. They are also far easier to change: the script is read
at load, so you can hide a field or rename a column and reload to see it.

Take the Lua ones if you do not want to compile anything, and these if you want the
speed and the integration a built-in dissector has.

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
