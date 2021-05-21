+++
title = "on > copy"
weight = 408
+++

A file to copy when the event is triggered.

Used by: [on](../on#blocks)


## Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `from` | `string` | The source file to copy from. Absolute paths reference the file system while relative paths are against the manifest source bundle. |
| `to` | `string` | The relative destination to copy to, based on the context. |
