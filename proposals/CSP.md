# WebAssembly Content Security Policy

This proposal describes a recommendation to the WebAppSec WG to extend Content Security Policy
(CSP) to support compiling and executing WebAssembly modules.

## Background: Security and WebAssembly

WebAssembly has a sandbox-style security model which focuses on limiting the potential damage a WebAssembly module can do to its host environment. This means that a WebAssembly module cannot invoke any functions from the host other than those explicitly passed to it via imports. Similarly, a WebAssembly module cannot directly access the evaluation stack; which also limits the potential for attacks based on buffer-overflows.

This does not, however, provide any guarantees that WebAssembly modules compute correct results: it is still possible that an incorrectly programmed module may corrupt data, produce invalid results and be subject to buffer-overflows that corrupt memory. Since the memory used by a WebAssembly module may be shared via ArrayBuffers and SharedArrayBuffers these faults may be visible to and affect other WebAssembly and JavaScript modules that also share the same memory. Other memory faults - such as use-after-free and accessing uninitialized memory - are also similarly not protected against.

In addition, the security model does not manage _which_ WebAssembly modules are executed; a malicious module may be completely safe in terms of the resources from the host that it uses and still cause significant harm to the user. Controlling which WebAssembly modules are executed is the primary focus of this note.

### CSP Threat Model and Use Cases

CSP, broadly, allows developers to control what resources can be loaded as part
of a site. These resources can include images, audio, video, or scripts. Loading
untrusted resources can lead to a variety of undesirable outcomes. Malicious
scripts could exfiltrate data from the site. Images could display misleading or
incorrect information. Fetching resources leaks information about the user to
untrusted third parties. [

This document describes a recommendation for how policy for handling
WebAssembly resources (modules) can be incorporated into CSP.

### Out of Scope Threats

* **Bugs in the browser**. We assume correct implementations of image decoders,
  script compilers, etc. CSP does not protect against malicious inputs that can,
  for example, trigger buffer overflows.
* **Resource exhaustion**. Computation performed by scripts uses memory and CPU
  time and can therefore cause a denial of service on the browser. Protecting
  against this is one reason site owners use CSP, but denial of service is not a
  first order consideration for CSP. Scripts are dangerous not because of their
  resource consumption but because of other effects that can cause.

## WebAssembly and CSP

Rather than focusing on the risks associated with imports and shared memory, CSP
allows developers to manage what code they are willing to run on their site. CSP will be
used to define what sources for Wasm bytes are trusted to instantiate and run.

### Summary of WebAssembly APIs and Their Risks

This section introduces the APIs provided by WebAssembly that are relevant to
Content Security Policy.

Executing WebAssembly has several steps. First there are the raw WebAssembly
bytes, which typically are loaded using the [fetch
API](https://fetch.spec.whatwg.org/). Next, the bytes are compiled using
`WebAssembly.compile` or `WebAssembly.compileStreaming` into a
`WebAssembly.Module`. This module is not yet executable, but WebAssembly
implementations may choose to translate the WebAssembly code into machine code
at this step. Finally, a WebAssembly module
is combined with an _import object_ using `WebAssembly.instantiate` to create an
`WebAssembly.Instance` object. The import object, broadly, defines the
capabilities of the resulting instance, optionally including a
`WebAssembly.Memory`, bindings for the WebAssembly function imports, and an
indirect function call table.  It is at this point that the WebAssembly code is
actually executable, as the host code can call WebAssembly functions through the
instance's exports.

These steps provide the core of the WebAssembly API, but there are several other
methods provided as well. These are summarized below along with their risks that
are related to CSP.

[**`WebAssembly.validate`**](https://webassembly.github.io/spec/js-api/index.html#dom-webassembly-validate)
checks whether the given bytes comprise a valid WebAssembly program. In other
words, it checks whether the bytes are syntactically correct and valid according
to the WebAssembly type system.

_Risks:_ None.

[**`new WebAssembly.Module`**](https://webassembly.github.io/spec/js-api/index.html#dom-module-module)
synchronously creates a `WebAssembly.Module` from WebAssembly bytes. This is a
synchronous version of `WebAssembly.compile`.

_Risks:_ many implementations will generate machine code at this step, even
though it is not yet exposed as executable code to the surrounding program. 

In the future there may be some _compile-time_ imports provided at this stage. In that event, compiling a module 
shares many of the same risks exposed by instantiating a module -- depending on the exact capabilities defined by such an extension to WebAssembly.

[**`WebAssembly.compile`**](https://webassembly.github.io/spec/js-api/index.html#dom-webassembly-compile)
provides a `Promise` that resolves to a `WebAssembly.Module` generated from the
provided WebAssembly bytes. This is an asynchronous version of `new
WebAssembly.Module`.

_Risks:_ equivalent to `new WebAssembly.Module`.

[**`WebAssembly.compileStreaming`**](https://webassembly.github.io/spec/web-api/index.html#dom-webassembly-compilestreaming)
creates a `WebAssembly.Module` from the WebAssembly bytes contained in the
provided `Response` object.

_Risks:_ equivalent to `new WebAssembly.Module`.

[**`WebAssembly.instantiate`**](https://webassembly.github.io/spec/js-api/index.html#dom-webassembly-instantiate)
accepts either WebAssembly bytes or a `WebAssembly.Module` and an import object.
The function returns a `WebAssembly.Instance` that allows executing the
WebAssembly code. If WebAssembly bytes are provided, `instantiate` will first
perform the steps of `WebAssembly.compile`.

_Risks:_ loads executable code into the running program. This code is confined,
being only able to access objects reachable from the import object. The instance
does not have unrestricted access to the JavaScript global object.

[**`WebAssembly.instantiateStreaming`**](https://webassembly.github.io/spec/web-api/index.html#dom-webassembly-instantiatestreaming)
accepts a `Response` containing WebAssembly bytes and an import object, performs
the operations behind `WebAssembly.compileStreaming` on these bytes and then
creates a `WebAssembly.Instance`.

_Risks:_ equivalent to `WebAssembly.instantiate`.

### Recommended Application of CSP

CSP policies can be used to restrict the construction of `WebAssembly.Module` objects.
Given the threat model for CSP, operations that load Wasm bytes over the network
or create `WebAssembly.Module` objects from raw bytes should be subject to CSP
restrictions.

Instantiating `WebAssembly.Module` objects is considered safe.
Unlike JavaScript `eval`, WebAssembly is capabilities-based: an instance
may only access the functionality explicitly supplied to it as imports and cannot directly
access ambient state such as the JavaScript global object.

Protecting the JavaScript-supplied imports to a WebAssembly module is orthogonal
to CSP directives for WebAssembly.
Thus instantiating `WebAssembly.Module` objects need not be subject to CSP
restrictions.

## Behavior of Current Implementations

All implementations currently permit all the WebAssembly operations they
support if there is no Content-Security-Policy specified.

All implementations currently permit all the WebAssembly operations they
support if there is a Content-Security-Policy specified
and `script-src` includes the 'unsafe-eval' directive.

Implementations vary as to which WebAssembly operations are allowed
if there is a Content-Security-Policy specified and
`script-src` does not include the 'unsafe-eval' directive.
The following table describes which operations are allowed in this case:

Operation | Chrome | Safari | Firefox | Edge
--- | --- | --- | --- | --- 
WebAssembly.validate | yes | yes | yes | yes
new WebAssembly.Module | no | yes | yes | yes
WebAssembly.compile | no | yes | yes | yes
WebAssembly.compileStreaming | no | yes | yes | yes
new WebAssembly.Instance | ? | ? | ? | ?
WebAssembly.instantiate(WebAssembly.Module, ...) | no | no | yes | yes
WebAssembly.instantiate(BufferSource, ...) | no | no | yes | yes
WebAssembly.instantiateStreaming | no | no | yes | yes
new WebAssembly.CompileError | yes | yes | yes | yes
new WebAssembly.LinkError | yes | yes | yes | yes
new WebAssembly.Table | yes | no | yes | yes
new WebAssembly.Memory | yes | no | yes | yes

The type of exception thrown when one of the above operations is disallowed
also varies by implementation.
This table lists the exception type for each implementation:

Browser | Thrown if disallowed
--- | --
Chrome | WebAssembly.CompileError: Wasm code generation disallowed in this context
Safari | EvalError
Firefox | N/A
Edge | ??

For references here is how each brower handles eval():

Browser | Thrown if disallowed
--- | --
Chrome | EvalError
Safari | EvalError
Firefox | Disallows script (uncatchable)
Edge | ??


## Proposed Homogenization of Existing Behavior

Motivating Principles:

* Be conservative about what is allowed.
* Allow operations which cannot be origin bound within
  the current API surface (Chrome's behavior).
   * Allow Memory and Table objects, because they are tied to
     the current origin,
     will be needed when compilation / instantiation is origin bound,
     have no parameters allowing an explicit origin.
   * Disallow compilation, as it can be used to exercise WebAssembly
     code compilation if an injection attack is present.
* Throw an EvalError (Safari's behavior), as this is what both
  Chrome and Safari do for eval(). NOTE: Firefox's behavior is even more
  conservative, but this might be challenging for others as it is more
  strict than for eval().

This table describes which operations should be allowed when
there is a Content-Security-Policy specified and
`script-src` does not include the 'unsafe-eval' directive:

Operation | Result
--- | ---
WebAssembly.validate | yes
new WebAssembly.Module | no
WebAssembly.compile | no
WebAssembly.compileStreaming | no
new WebAssembly.Instance | yes
WebAssembly.instantiate(WebAssembly.Module, ...) | yes
WebAssembly.instantiate(BufferSource, ...) | no
WebAssembly.instantiateStreaming | no
new WebAssembly.CompileError | yes
new WebAssembly.LinkError | yes
new WebAssembly.Table | yes
new WebAssembly.Memory | yes


## Proposed 'wasm-eval' Directive

WebAssembly compilation is less prone to being spoofed in the way
JavaScript is. Further, WebAssembly has an explicitly specified scope,
further reducing the likelihood of injection attacks.

While origin bound / known hash operations are always safer,
it is useful to have a mechanism to allow WebAssembly content
in a CSP policy that would otherwise disallow it, without being
required to also allow JavaScript eval().

NOTE: Providing a directive to allow JavaScript eval() without WebAssembly
doesn't seem immediately useful, and so has been left out intentionally.

We propose:
* Allow the 'wasm-eval' directive under each directive that currently
  supports 'unsafe-eval' (this is currently all directives because
  directives can defer to each other).
* For the `script-src` directive (directly or by reference),
  interpret 'wasm-eval' to mean
  that all WebAssembly operations should be allowed.
  (Without allowing JavaScript eval()).


## Proposed Origin Bound Permission

In order to make WebAssembly more useful within the spirit of CSP,
we should permit `Response` objects to carry trusted origin information.
This will allow compilation and instantiation of WebAssembly
in a natural way within a CSP.

Proposed Changes:
* Response.url will be "hardened" to allow it (or it with a taint track bit)
  to be trusted to carry information regarding the origin of a fetch
  response.
* WebAssembly compilation / instantiation requests that would
  be allowed if they were script src's for non-inline JavaScript
  will also be allowed for WebAssembly.
   * This applies to hashes, or to origin whitelisting.
* This sub-proposal only affects WebAssembly.compileStreaming
  and WebAssembly.instatiateStreaming
  
### CSP Policy Application Summary

The checks performed for web assembly operations is summarized as follows:

Operation | default | no unsafe-eval | with wasm-eval | with unsafe-eval and wasm-eval 
--- | --- | --- | --- | ---
JavaScript eval                                  | allow | SRI-hash | SRI-hash | allow
new WebAssembly.Module(bytes)                    | allow | SRI-hash | allow | allow 
WebAssembly.compile(bytes)                       | allow | SRI-hash | allow | allow 
WebAssembly.instantiate(bytes, ...)              | allow | SRI-hash | allow | allow 
WebAssembly.instantiate(module, ...)             | allow | allow | allow | allow 
WebAssembly.compileStreaming(Response)           | allow | script-src | script-src | script-src 
WebAssembly.instantiateStreaming(Response, ...)  | allow | script-src | script-src | script-src
WebAssembly.validate(bytes)                      | allow | allow | allow | allow 
new WebAssembly.Instance(module)                 | allow | allow | allow | allow 
new WebAssembly.CompileError                     | allow | allow | allow | allow 
new WebAssembly.LinkError                        | allow | allow | allow | allow 
new WebAssembly.Table                            | allow | allow | allow | allow 
new WebAssembly.Memory                           | allow | allow | allow | allow 

Where SRI-hash means applying sub-resource-integrity checks based on the hash of the supplied bytes,
rejecting the operation if the hash does not match whitelisted hashes,
and script-src means rejecting operations that are not allowed by the CSP
policy's directives for the source of scripts, e.g. script-src restricting origins.
Note that `unsafe-eval` effectively *implies* `wasm-eval`.
### Examples

```
Content-Security-Policy: script-src 'self';

WebAssembly.compileStreaming(fetch('/foo.wasm'));  // OK
WebAssembly.instantiateStreaming(fetch('/foo.wasm')); // OK
WebAssembly.compileStreaming(fetch('/foo.js'));  // BAD: mime type
WebAssembly.instantiateStreaming(fetch('/foo.js')); // BAD: mime type
WebAssembly.compileStreaming(fetch('http://yo.com/foo.wasm'));  // BAD: cross origin
WebAssembly.instantiateStreaming(fetch('http://yo.com/foo.wasm')); // BAD: cross origin
```

```
Content-Security-Policy: script-src http://yo.com;

WebAssembly.compileStreaming(fetch('http://yo.com/foo.wasm'));  // OK
WebAssembly.instantiateStreaming(fetch('http://yo.com/foo.wasm')); // OK
```

```
Content-Security-Policy: script-src 'sha256-123...456';

WebAssembly.compileStreaming(fetch('http://baz.com/hash123..456.wasm'));  // OK
WebAssembly.instantiateStreaming(fetch('http://baz.com/hash123..456.wasm')); // OK
```
