[![Wireshark](https://github.com/Open-Markets-Initiative/Open-Markets-Initiative/blob/main/About/Images/Wireshark.png)](https://www.wireshark.org)

# Omi Wireshark C Dissectors

These dissectors are published for two reasons. For preview before they are merged
into released Wireshark, and so that you can build them into a Wireshark of your own,
for your own use. Compile them into a Wireshark you build and run, and read your own
captures with them.

## Use

These dissectors are published so that you can **build them into a Wireshark of your own, for your own use**.
Generate them, compile them into a Wireshark you build and run, and read your own captures with them.

They are **not** a contribution to the Wireshark project, and publishing them here does not offer them as one.

> Only authorized users of the Open Markets Initiative may place this code into the Wireshark build.

That covers submitting it to `wireshark/wireshark`, carrying it in a Wireshark
distribution or package, and shipping it inside any Wireshark binary offered to
others. Those rights are reserved and are not granted by this repository.

A Wireshark you build for yourself is yours to build. Wireshark itself is
GPL-2.0-or-later, and nothing here restricts what you do privately with a build
you make; the reservation is on putting this code into builds handed to others.

[License](License) states this in full and is the text that governs.

Each dissector is generated. Edits belong in the model or the configuration it
was generated from, never in the C, which is overwritten on the next run.

| Protocol | Dissector | Filter | Versions |
| --- | --- | --- | --- |
| [CoinbaseDerivatives MarketDataApi](Coinbase/MarketDataApi/ReadMe.md) | `packet-coinbasederivatives-marketdataapi.c` | `coinbasederivatives.marketdataapi` | 1.9, 1.7, 1.3, 1.2 |
| [IexEquities Tops](Iex/Tops/ReadMe.md) | `packet-iexequities-tops.c` | `iexequities.tops` | 1.66, 1.64, 1.56 |
| [NsmEquities TotalView](Nasdaq/TotalView/ReadMe.md) | `packet-nsmequities-totalview.c` | `nsmequities.totalview` | 5.0.2026, 5.0.2023, 5.0.2022, 5.0.2018, 5.0.2017, 4.1, 3.2, 4.0, 3.1, 3.1.f, 4.0.f, 3.0, 2.0.a, 2.0, 1.0 |

[Omi.Directory]: https://github.com/Open-Markets-Initiative/Open-Markets-Initiative "Open Markets Initiative"
[Omi.Glossary]: https://github.com/Open-Markets-Initiative/Open-Markets-Initiative/tree/main/About "Omi Glossary"
[Wireshark.Lua.Repository]: https://github.com/Open-Markets-Initiative/omi-wireshark-lua "Omi Lua Wireshark Dissectors"
