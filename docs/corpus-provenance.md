# Corpus provenance and accuracy boundary

This document records what is currently included in the repository and what is
required before making a real-world accuracy claim.

## Included corpus

`testdata/eml/` contains 203 messages:

- 3 hand-written demonstration messages;
- 100 deterministic synthetic phishing variants;
- 100 deterministic synthetic clean variants.

The synthetic messages are useful for regression testing parser and signal
behavior. They are not a representative sample of operational mail and their
macro-F1 score must not be presented as production accuracy.

The expected labels live in `testdata/expected/`. Re-run the offline gate with:

```powershell
go run ./cmd/phishlens eval --dir testdata/eml --expected testdata/expected --min-f1 0.9
```

## External source under review

The Apache SpamAssassin project publishes a Public Corpus and describes its
categories and message counts in the [official corpus README][corpus-readme].
The project also maintains an official [downloads page][downloads]. These are
the source references to use when evaluating an external benchmark import.

At the time of this record, the corpus README does not provide a clear dataset
license or redistribution grant. Therefore the raw messages are deliberately
not vendored, downloaded by CI, or counted in the repository's F1 gate. A legal
owner must confirm the terms before importing or redistributing them.

## Import requirements

Any future public or licensed corpus must be added outside the synthetic gate
with a manifest containing, for every source collection:

1. source URL and retrieval date;
2. license or written permission, including the exact text or a durable link;
3. original category mapping and the PhishLens label mapping;
4. a SHA-256 checksum for the downloaded archive and the unpacked files;
5. de-identification/PII handling and any redistribution restrictions;
6. a reproducible command or script that produces the evaluation split.

The benchmark report must show synthetic and external results separately, with
the source, split, label mapping, and exclusions visible. A green synthetic
F1 gate alone is not evidence of real-world accuracy.

[corpus-readme]: https://spamassassin.apache.org/old/publiccorpus/readme.html
[downloads]: https://spamassassin.apache.org/downloads.cgi
