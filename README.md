# Modern header-only C++20 ASN.1 DER parser library

## Key features
- Quickly parse ASN.1 DER directly to C++ types and structures without any intermediate representation.
- Write ASN.1 specifications directly in C++, no additional ASN.1 compilation steps are required.
- In case of parse errors, get detailed error context messages.
- No heavy dependencies like OpenSSL. The only dependency is Boost.PFR, which is also header-only.
- Can parse advanced structures like `X.509` or `PKCS #7` - see below.

## Additional features
- Supports validators, which can be used to validate parsed data on the go.
- Supports recursive ASN.1 (with recursion depth limiting).
- Validates many ASN.1 data structures (like `OBJECT IDENTIFIER`, `UtcTime`, `GeneralizedTime`).
- Works with iterators.
- Wide C++ type support.
- Easily extensible.
- Can parse without heap memory allocations (with right C++ types provided).

## Current limitations
- Encoding to DER is not supported.
- Versioning is only partially supported for `SEQUENCE`.
- No support for some rare ASN.1 types: `EXTERNAL/INSTANCE OF`, `REAL`, `EMBEDDED PDV`, `CHARACTER STRING`.
- No support for newer ASN.1 types: `DATE`, `DATE-TIME`, `DURATION`, `TIME`, `TIME-OF-DAY`.
- No support for new ASN.1 information objects, open types syntax (`CLASS`, `WITH SYNTAX` keywords), you will have to stick with `ANY`.
- Support only for single-byte tags.
- No validation of string type contents.
- No verification if incoming `SET` and `SET OF` structures are sorted (as DER requires).
- No verification if a `SEQUENCE` is declared unambiguously (if all the tags are unique and correct).
- Fully supports random access iterators. Limited support of forward iterators.

## Requirements
- C++20 compiler (tested with MSVC 17.4.2, GCC 11.3.0 and Clang 14.0.0).
- Boost.PFR (also a header-only library).

## ASN.1 to SimpleAsn1
| ASN.1 notation | SimpleAsn1 C++ specification | Corresponding C++ data structure |
| ----------- | ----------- | ----------- |
| `ANY`       | `asn1::spec::any` | `std::span<const ByteType>` or `std::vector<ByteType>` |
| `BIT STRING`   | `asn1::spec::bit_string`  | `asn1::bit_string<std::span<const ByteType>>` or `asn1::bit_string<std::vector<ByteType>>` |
| `BOOLEAN`   | `asn1::spec::boolean`  | `bool` |
| `CHOICE`   | `asn1::spec::choice`, `asn1::spec::choice_with_options`  | `std::variant` |
| `INTEGER`   | `asn1::spec::integer`  | Any C++ signed integral type (`std::int8_t`, `std::int16_t`, `std::int32_t`, `std::int64_t`) or `std::vector<ByteType>`/`std::span<const ByteType>` for arbitrary-sized integers |
| `ENUMERATED`   | `asn1::spec::enumerated`  | Any `enum` or `enum class`, or any C++ signed integral type |
| `NULL`   | `asn1::spec::null`  | `std::nullptr_t` |
| `OBJECT IDENTIFIER`   | `asn1::spec::object_identifier`  | `std::span<const ByteType>` or `std::vector<ByteType>` to read an OID as is without trying to decode. `asn1::decoded_object_identifier<std::vector<AnyUnsignedIntegerType>>` to make the library decode the OID |
| `OCTET STRING`   | `asn1::spec::octet_string`  | `std::span<const ByteType>` or `std::vector<ByteType>` |
| `RELATIVE-OID`   | `asn1::spec::relative_oid`  | `std::span<const ByteType>` or `std::vector<ByteType>` to read an OID as is without trying to decode. `asn1::decoded_object_identifier<std::vector<AnyUnsignedIntegerType>>` to make the library decode the OID |
| `SEQUENCE`  | `asn1::spec::sequence`, `asn1::spec::sequence_with_options` | C++ aggregate `struct` |
| `SET`  | `asn1::spec::set`, `asn1::spec::set_with_options` | C++ aggregate `struct` |
| `SEQUENCE OF`  | `asn1::spec::sequence_of`, `asn1::spec::sequence_of_with_options` | `std::vector`, `std::list`, `std::deque` or other type with `emplace_back()` method |
| `SET OF`  | `asn1::spec::set_of`, `asn1::spec::set_of_with_options` | `std::vector`, `std::list`, `std::deque` or other type with `emplace_back()` method |
| `NumericString`, `PrintableString`, `IA5String`, `TeletexString`, `VideotexString`, `VisibleString`, `GraphicString`, `GeneralString`, `ObjectDescriptor` | `asn1::spec::numeric_string`, `asn1::spec::printable_string`, `asn1::spec::ia5_string`, `asn1::spec::teletex_string`, `asn1::spec::videotex_string`, `asn1::spec::visible_string`, `asn1::spec::graphic_string`, `asn1::spec::general_string`, `asn1::spec::object_descriptor` | `std::string` to decode the string; `std::span<const ByteType>` or `std::vector<ByteType>` to read raw string bytes |
| `UniversalString`  | `asn1::spec::universal_string` | `std::u32string` to decode the string; `std::span<const ByteType>` or `std::vector<ByteType>` to read raw string bytes |
| `BMPString`  | `asn1::spec::bmp_string` | `std::u16string` to decode the string; `std::span<const ByteType>` or `std::vector<ByteType>` to read raw string bytes |
| `UTF8String`  | `asn1::spec::utf8_string` | `std::u8string` or `std::string` to decode the string; `std::span<const ByteType>` or `std::vector<ByteType>` to read raw string bytes |
| `GeneralizedTime`  | `asn1::spec::generalized_time` | `asn1::generalized_time` |
| `UTCTime`  | `asn1::spec::utc_time` | `asn1::utc_time` |
| `OPTIONAL`  | `asn1::spec::optional` | `std::optional`, `std::unique_ptr`, `std::shared_ptr` |
| `DEFAULT`  | `asn1::spec::optional_default` with `asn1::spec::default_value` | Nested C++ type as is |
| Tags  | `asn1::spec::tagged`, `asn1::spec::tagged_with_options` | Nested C++ type as is |
| Recursion  | C++ struct inherited from `asn1::spec::recursive`. Recursive specs should be `asn1::spec::variant` or `asn1::spec::optional` | Recursive types should be `std::unique_ptr` or `std::shared_ptr` |

* `ByteType` can be `char`, `std::int8_t`, `std::uint8_t` or `std::byte`.
* You can use any compatible range instead of `std::span<const ByteType>` or `std::vector<ByteType>`. The only required operation is `range = Range{ iterator, iterator }`, where `Range` is your selected type, and `iterator` is the iterator type you pass to the `asn1::der::decode` method.

## Simple example
Let's take a look at the following ASN.1 declarations:
```
MyChoice ::= CHOICE {
	firstChoice      [1] IMPLICIT INTEGER,
	secondChoice     [2] EXPLICIT OCTET STRING,
	thirdChoice      IA5String
}

SomeDataStructure  ::=  SEQUENCE  {
	integralValue      INTEGER  DEFAULT 123,
	booleanValue       BOOLEAN  OPTIONAL,
	choiceValue        MyChoice,
	listOfValues       SET OF INTEGER
}
```
They can be transformed to the corresponding C++ SimpleAsn1 declarations like this:
```cpp
namespace my_spec {
using my_choice = asn1::spec::choice<
	asn1::spec::tagged<
		1, asn1::spec::encoding::impl, asn1::spec::cls::context_specific,
		asn1::spec::integer<>
	>,
	asn1::spec::tagged<
		2, asn1::spec::encoding::expl, asn1::spec::cls::context_specific,
		asn1::spec::ia5_string<>
	>,
	asn1::spec::octet_string<>
>;

using some_data_structure = asn1::spec::sequence<
	asn1::spec::optional_default<asn1::spec::default_value<123>, asn1::spec::integer<>>,
	asn1::spec::optional<asn1::spec::boolean<>>,
	my_choice,
	asn1::spec::set_of<asn1::spec::integer<>>
>;
} // namespace my_spec
```
As you can see, ASN.1 transforms to the C++ declarations pretty closely. Now let's implement the corresponding C++ data structures, which would store the parsed ASN.1 DER data:
```cpp
using my_choice = std::variant<
	std::int32_t,
	std::string,
	std::span<const std::uint8_t>>;

struct some_data_structure
{
	std::int64_t integral_value;
	std::optional<bool> boolean_value;
	my_choice choice_value;
	std::vector<std::int16_t> list_of_values;
};
```
According to the table above, we can use any C++ signed integer type for `INTEGER`s, or even `std::span<const std::uint8_t>` if we don't want decode an integer
(or if we expect too large integers, which don't fit in the built-in C++ types). The `span` will contain a range of bytes representing the integer
(without the ASN.1 type and length bytes).
For `OPTIONAL`, we can use `std::optional`, `std::shared_ptr` or `std::unique_ptr`. `SET OF` and `SEQUENCE OF` can be represented as a `std::vector`
of corresponding values (or any other C++ type, which provides an `emplace_back` method). `SEQUENCE` translates into a `struct`, and `CHOICE` into a `std::variant`.
Now, let's use the specification and the data structures we created to parse real ASN.1 data:
```cpp
// DER-encoded data
std::vector<std::uint8_t> der{
	0x30, 0x13, // SEQUENCE
		0x01, 0x01, 0xff, // BOOLEAN
		0xa2, 0x05, 0x16, 0x03, 'a', 'b', 'c', // CHOICE with IA5String
		0x31, 0x07, //SET OF
			0x02, 0x02, 0x10, 0x20, //INTEGER
			0x02, 0x01, 0x25 //INTEGER
};

auto result = asn1::der::decode<
	some_data_structure, // Data structure to use for parsing
	my_spec::some_data_structure // Our specification
>(der.begin(), der.end());

// result now contains the decoded some_data_structure!

// This integer is absent in the encoded ASN.1,
// so the default value (123) is assigned automatically.
EXPECT_EQ(result.integral_value, 123);

EXPECT_EQ(result.boolean_value, true);

// For choice, IA5String is selected,
// which we asked to decode to std::string:
auto choice_value = std::get_if<std::string>(&result.choice_value);
ASSERT_NE(choice_value, nullptr);
EXPECT_EQ(*choice_value, "abc");

EXPECT_EQ(result.list_of_values, (std::vector<std::int16_t>{ 0x1020, 0x25 }));
```

## Specification element names and other options
You can add optional names to specification elements. Names are used to provide better context in case of parser errors.
For example, you could re-write the specification from the previous example like this:
```cpp
namespace my_spec {
using my_choice = asn1::spec::choice_with_options<
	asn1::opts::named<"MyChoice">,
	asn1::spec::tagged_with_options<
		1, asn1::spec::encoding::impl, asn1::spec::cls::context_specific,
		asn1::opts::named<"Tag1">,
		asn1::spec::integer<asn1::opts::named<"IntChoice">>
	>,
	asn1::spec::tagged_with_options<
		2, asn1::spec::encoding::expl, asn1::spec::cls::context_specific,
		asn1::opts::named<"Tag2">,
		asn1::spec::ia5_string<asn1::opts::named<"IA5StringChoice">>
	>,
	asn1::spec::octet_string<asn1::opts::named<"OctetStringChoice">>
>;

using some_data_structure = asn1::spec::sequence_with_options<
	asn1::opts::named<"SomeDataStructure">,
	asn1::spec::optional_default<asn1::spec::default_value<123>,
		asn1::spec::integer<asn1::opts::named<"IntValue">>>,
	asn1::spec::optional<asn1::spec::boolean<
		asn1::opts::named<"BoolValue">>
	>,
	my_choice,
	asn1::spec::set_of_with_options<asn1::opts::named<"ListOfValues">,
		asn1::spec::integer<asn1::opts::named<"IntFromList">>
	>
>;
} //namespace my_spec
```

`asn1::opts::named<...>` is a short alias for `asn1::opts::options<asn1::opts::name<...>>`. Some specification elements support other options, too.
For example, you can specify min and max number of elements (along with the name) for `SET OF` or `SEQUENCE OF` like this:
```cpp
asn1::spec::set_of_with_options<
	asn1::opts::options<
		asn1::opts::name<"ListOfValues">,
		asn1::opts::min_max_elements<1, 5>>,
	asn1::spec::integer<asn1::opts::named<"IntFromList">>
>
```

## Error handling and error context
If ASN.1 is invalid or does not match the specification, SimpleAsn1 will throw `asn1::parse_error`. The exception object contains an error message (`e.what()`)
and a context vector (`e.get_context()`), which can help to understand where the parsing process has stopped. By default, full context will be returned, but this can be tuned
(you can select either full context, or the context for the last node which failed only, or omit all context completely).
Full context is free at runtime, you don't pay any CPU cycles or memory until the exception object is constructed. Full context is used by default.

Let's try to parse invalid ASN.1 data with the specification from the previous example, we'll get a nice error message with full context.
We can also use another `asn1::der::decode` overload with parser state crafted manually, so that we'll be able to figure out the exact position where the parser has stopped:
```cpp
std::vector<std::uint8_t> der{
	0x30, 0x13, // SEQUENCE
		0x01, 0x01, 0xff, // BOOLEAN
		// CHOICE with tagged IA5String, but the IA5String tag is wrong!
		// (0x17 instead of 0x16)
		0xa2, 0x05, 0x17, 0x03, 'a', 'b', 'c',
		0x31, 0x07, //SET OF
			0x02, 0x02, 0x10, 0x20, //INTEGER
			0x02, 0x01, 0x25 //INTEGER
};

asn1::decode_state state(der.begin(), der.end());

try
{
	asn1::der::decode<some_data_structure,
		my_spec::some_data_structure>(state);
}
catch (const asn1::parse_error& e)
{
	std::cerr << "ASN1 parse error: " << e.what()
		<< " at byte #" << std::distance(der.begin(), state.begin) << '\n';
	if (!e.get_context().empty())
	{
		std::cerr << "Context: ";
		const char* sep = "";
		for (const auto& ctx : e.get_context())
		{
			std::cerr << sep << ctx.spec_type;
			if (!ctx.spec_name.empty())
				std::cerr << " (" << ctx.spec_name << ")";
			sep = "\n -> ";
		}
		std::cerr << '\n';
	}
}
```

This code will produce a nice error message:
```
ASN1 parse error: Expected IA5String at byte #9
Context: SEQUENCE (SomeDataStructure)
 -> CHOICE (MyChoice)
 -> TAGGED (Tag2)
 -> IA5String (IA5StringChoice)
```
As you can see, error context contains both ASN.1 notation names and the names we provided.

You can change the level of context by using `asn1::decode_options`, for example:
```cpp
asn1::der::decode<some_data_structure,
	my_spec::some_data_structure,
	asn1::decode_options<
		asn1::decode_opts::error_context_policy::no_context
	>>(state);
```
Changing the level of context will improve the build time and reduce the binary size, but the runtime speed (when parse errors do not occur) will not be affected.

## Validation (a.k.a subtyping in ASN.1)
You can optionally validate almost any element to break the parsing process early if a mistake is encountered. For example:
```cpp
constexpr auto int_value_valudator = [](int val) {
	if (val > 100)
		throw std::runtime_error("Invalid IntValue");
};

using some_data_structure = asn1::spec::sequence_with_options<
	asn1::opts::named<"SomeDataStructure">,
	asn1::spec::optional_default<asn1::spec::default_value<123>,
		asn1::spec::integer<asn1::opts::named<"IntValue">>>,
	asn1::spec::optional<asn1::spec::boolean<
		asn1::opts::named<"BoolValue">>
	>,
	my_choice,
	asn1::spec::set_of_with_options<asn1::opts::named<"ListOfValues">,
		asn1::spec::integer<asn1::opts::options<
			asn1::opts::name<"IntFromList">,
			// Set a validator for this INTEGER
			asn1::opts::validator_func<int_value_valudator>
		>>
	>
>;
```

Here, we added a validator to each integer from `SET OF`. If any value is greater than `100`, `SimpleAsn1` will throw `asn1::parse_error` with context (as usual),
but in this case, the exception object will additionally contain a nested exception, which was thrown from the validator lambda.

## Advanced examples
SimpleAsn1 can parse more advanced ASN.1 structures, like `X.509` or `PKCS #7`.
- See SimpleAsn1 unit tests for more use cases, like parsing recursive structures (`RecursiveVariantLinkedList`, `RecursiveOptionalLinkedListWithRecursionDepth` tests).
- X509Reader is a SimpleAsn1-based X.509 DER parser, which parses `base64` representations of certificate files (usually stored with `.cer` or `.ctr` extensions).

<details>
<summary>**X509Reader output for the `google.com` website certificate (click)**</summary>
```
Signature algorithm: 1.2.840.113549.1.1.11 SHA256 with RSA
PKI algorithm: 1.2.840.10045.2.1 EC public key
Version: 2
Valid not before: 2022-11-02 13:43:09
Valid not after: 2023-01-25 13:43:08
Serial number: 00 ee 64 2c f8 39 97 9c c9 12 42 56 26 a7 c4 6d 0a
Issuer:
  Name:
    Attribute: 2.5.4.6 (Country Name)
    Value: US
  Name:
    Attribute: 2.5.4.10 (Organization Name)
    Value: Google Trust Services LLC
  Name:
    Attribute: 2.5.4.3 (Common Name)
    Value: GTS CA 1C3


Subject:
  Name:
    Attribute: 2.5.4.3 (Common Name)
    Value: *.google.com

Extensions:

ID: 2.5.29.15
Critical: YES
Key usage extension
 * Digital Signature

ID: 2.5.29.37
Critical: NO
Ext key usage extension
Usage: 1.3.6.1.5.5.7.3.1 (Server Auth)

ID: 2.5.29.19
Critical: YES
Basic constraints extension
CA: NO

ID: 2.5.29.14
Critical: NO
Subject key identifier extension
4e 17 79 4e ae ac 2a 1d 45 70 1a ff 56 18 9a 5a c0 02 46 d6

ID: 2.5.29.35
Critical: NO
Authority key identifier extension
Key ID:
8a 74 7f af 85 cd ee 95 cd 3d 9c d0 e2 46 14 f3 71 35 1d 27

ID: 1.3.6.1.5.5.7.1.1
Critical: NO
Authority info access extension
Uniform resource identifier: http://ocsp.pki.goog/gts1c3
Access method: 1.3.6.1.5.5.7.48.1 (OCSP)
Uniform resource identifier: http://pki.goog/repo/certs/gts1c3.der
Access method: 1.3.6.1.5.5.7.48.2 (CA Issuers)

ID: 2.5.29.17
Critical: NO
Subject alt name extension
DNS name: *.google.com
DNS name: *.appengine.google.com
DNS name: *.bdn.dev
DNS name: *.origin-test.bdn.dev
DNS name: *.cloud.google.com
DNS name: *.crowdsource.google.com
DNS name: *.datacompute.google.com
DNS name: *.google.ca
DNS name: *.google.cl
DNS name: *.google.co.in
DNS name: *.google.co.jp
DNS name: *.google.co.uk
DNS name: *.google.com.ar
DNS name: *.google.com.au
DNS name: *.google.com.br
DNS name: *.google.com.co
DNS name: *.google.com.mx
DNS name: *.google.com.tr
DNS name: *.google.com.vn
DNS name: *.google.de
DNS name: *.google.es
DNS name: *.google.fr
DNS name: *.google.hu
DNS name: *.google.it
DNS name: *.google.nl
DNS name: *.google.pl
DNS name: *.google.pt
DNS name: *.googleadapis.com
DNS name: *.googleapis.cn
DNS name: *.googlevideo.com
DNS name: *.gstatic.cn
DNS name: *.gstatic-cn.com
DNS name: googlecnapps.cn
DNS name: *.googlecnapps.cn
DNS name: googleapps-cn.com
DNS name: *.googleapps-cn.com
DNS name: gkecnapps.cn
DNS name: *.gkecnapps.cn
DNS name: googledownloads.cn
DNS name: *.googledownloads.cn
DNS name: recaptcha.net.cn
DNS name: *.recaptcha.net.cn
DNS name: recaptcha-cn.net
DNS name: *.recaptcha-cn.net
DNS name: widevine.cn
DNS name: *.widevine.cn
DNS name: ampproject.org.cn
DNS name: *.ampproject.org.cn
DNS name: ampproject.net.cn
DNS name: *.ampproject.net.cn
DNS name: google-analytics-cn.com
DNS name: *.google-analytics-cn.com
DNS name: googleadservices-cn.com
DNS name: *.googleadservices-cn.com
DNS name: googlevads-cn.com
DNS name: *.googlevads-cn.com
DNS name: googleapis-cn.com
DNS name: *.googleapis-cn.com
DNS name: googleoptimize-cn.com
DNS name: *.googleoptimize-cn.com
DNS name: doubleclick-cn.net
DNS name: *.doubleclick-cn.net
DNS name: *.fls.doubleclick-cn.net
DNS name: *.g.doubleclick-cn.net
DNS name: doubleclick.cn
DNS name: *.doubleclick.cn
DNS name: *.fls.doubleclick.cn
DNS name: *.g.doubleclick.cn
DNS name: dartsearch-cn.net
DNS name: *.dartsearch-cn.net
DNS name: googletraveladservices-cn.com
DNS name: *.googletraveladservices-cn.com
DNS name: googletagservices-cn.com
DNS name: *.googletagservices-cn.com
DNS name: googletagmanager-cn.com
DNS name: *.googletagmanager-cn.com
DNS name: googlesyndication-cn.com
DNS name: *.googlesyndication-cn.com
DNS name: *.safeframe.googlesyndication-cn.com
DNS name: app-measurement-cn.com
DNS name: *.app-measurement-cn.com
DNS name: gvt1-cn.com
DNS name: *.gvt1-cn.com
DNS name: gvt2-cn.com
DNS name: *.gvt2-cn.com
DNS name: 2mdn-cn.net
DNS name: *.2mdn-cn.net
DNS name: googleflights-cn.net
DNS name: *.googleflights-cn.net
DNS name: admob-cn.com
DNS name: *.admob-cn.com
DNS name: googlesandbox-cn.com
DNS name: *.googlesandbox-cn.com
DNS name: *.gstatic.com
DNS name: *.metric.gstatic.com
DNS name: *.gvt1.com
DNS name: *.gcpcdn.gvt1.com
DNS name: *.gvt2.com
DNS name: *.gcp.gvt2.com
DNS name: *.url.google.com
DNS name: *.youtube-nocookie.com
DNS name: *.ytimg.com
DNS name: android.com
DNS name: *.android.com
DNS name: *.flash.android.com
DNS name: g.cn
DNS name: *.g.cn
DNS name: g.co
DNS name: *.g.co
DNS name: goo.gl
DNS name: www.goo.gl
DNS name: google-analytics.com
DNS name: *.google-analytics.com
DNS name: google.com
DNS name: googlecommerce.com
DNS name: *.googlecommerce.com
DNS name: ggpht.cn
DNS name: *.ggpht.cn
DNS name: urchin.com
DNS name: *.urchin.com
DNS name: youtu.be
DNS name: youtube.com
DNS name: *.youtube.com
DNS name: youtubeeducation.com
DNS name: *.youtubeeducation.com
DNS name: youtubekids.com
DNS name: *.youtubekids.com
DNS name: yt.be
DNS name: *.yt.be
DNS name: android.clients.google.com
DNS name: developer.android.google.cn
DNS name: developers.android.google.cn
DNS name: source.android.google.cn

ID: 2.5.29.32
Critical: NO
Certificate policies extension
Policy ID: 2.23.140.1.2.1 (CA/Browser Forum domain-validated)
Policy ID: 1.3.6.1.4.1.11129.2.5.3 (Google Trust Services)

ID: 2.5.29.31
Critical: NO
CRL distribution points extension
Uniform resource identifier: http://crls.pki.goog/gts1c3/QqFxbi9M48c.crl

ID: 1.3.6.1.4.1.11129.2.4.2
Critical: NO
Signed certificate timestamp list extension
TLS-encoded data (not supported)
00 f0 00 76 00 e8 3e d0 da 3e f5 06 35 32 e7 57 28 bc 89 6b
c9 03 d3 cb d1 11 6b ec eb 69 e1 77 7d 6d 06 bd 6e 00 00 01
84 38 cb d8 8c 00 00 04 03 00 47 30 45 02 20 41 0d 4f bd 40
b9 a6 17 11 01 22 2c 08 a0 7c 64 79 31 3c 00 31 ec 5b 50 21
6a 40 55 4a 48 37 d1 02 21 00 b5 db c3 07 d0 5f 08 58 9b 6d
92 79 6a 01 19 53 86 0a 98 bb 2a 36 25 1c 01 01 54 2e 84 bc
c5 2f 00 76 00 7a 32 8c 54 d8 b7 2d b6 20 ea 38 e0 52 1e e9
84 16 70 32 13 85 4d 3b d2 2b c1 3a 57 a3 52 eb 52 00 00 01
84 38 cb d8 d8 00 00 04 03 00 47 30 45 02 21 00 9c 09 30 71
44 e9 f3 f5 9a ac 3d 7f 1a 49 92 02 8e 5e 0c e6 71 2b 4d 84
bc 70 6b 1e 40 51 34 8f 02 20 4f e7 2c 46 41 aa fa 0f f9 3c
44 51 de cc e2 63 3a d4 df 41 05 f7 cf 1b d1 00 fe 67 0d 66
47 4a
```
</details>

## Extensibility
You can add parsers for new primitive ASN.1 types or existing types into new C++ data structures.
The main extension point is `asn1::detail::der::der_decoder` structure, which has various specializations for different ASN.1 notations and C++ types.
For example, you could extend SimpleAsn1 to enable parsing of `INTEGER` values of arbitraty length into `boost::multiprecision::cpp_int` like this:
```cpp
#include "boost/multiprecision/cpp_int.hpp"

namespace asn1::detail::der
{
template<typename DecodeState,
	typename Options, typename ParentContexts, typename SpecOptions>
struct der_decoder<DecodeState, Options, ParentContexts, spec::integer<SpecOptions>,
	boost::multiprecision::cpp_int>
	: der_decoder_base<der_decoder<DecodeState, Options,
		ParentContexts, spec::integer<SpecOptions>, boost::multiprecision::cpp_int>>
{
	static constexpr const char* length_decode_error_text = "Expected INTEGER";

	static void decode_implicit_impl(length_type len, boost::multiprecision::cpp_int& value,
		DecodeState& state)
	{
		value = 0;
		if (!len)
			return;

		bool is_signed = static_cast<std::uint8_t>(*state.begin) & 0x80u;
		while (len--)
		{
			value <<= std::numeric_limits<std::uint8_t>::digits;
			auto byte = static_cast<std::uint8_t>(*state.begin++);
			value |= static_cast<std::uint8_t>(is_signed ? ~byte : byte);
		}
		if (is_signed)
			value = -value - 1;
	}
};
} //namespace asn1::detail::der

// Now, we can parse INTEGERs directly into boost::multiprecision::cpp_int:
std::vector<std::uint8_t> { 2, 2, 0x80, 0x22 }; // Signed integer: -32734
boost::multiprecision::cpp_int value;
asn1::der::decode<asn1::spec::integer<>>(
	wrapper.vec.begin(), wrapper.vec.end(), value);
EXPECT_EQ(value, -32734);
```
