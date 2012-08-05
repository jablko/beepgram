import base64, email.utils, hashlib, hmac, sys, urllib
from google.appengine.api import mail, urlfetch
from time import time

#   This specification defines the following method for percent-encoding
#   strings:
#
#   1.  Text values are first encoded as UTF-8 octets per [RFC3629] if
#       they are not already.  This does not include binary values that
#       are not intended for human consumption.
#
#   2.  The values are then escaped using the [RFC3986] percent-encoding
#       (%XX) mechanism as follows:
#
#       *  Characters in the unreserved character set as defined by
#          [RFC3986], Section 2.3 (ALPHA, DIGIT, "-", ".", "_", "~") MUST
#          NOT be encoded.
#
#       *  All other characters MUST be encoded.
#
#       *  The two hexadecimal characters used to represent encoded
#          characters MUST be uppercase.

percentEncode = lambda arg: urllib.quote(arg, '~')

key = '6vca60b7lP6KW2hbLhi9BJVds30ep2q1phIBqQOCDY&bHeW9i7aFohtoReoeWGmq56hz9gM5xHyF8cT7p1zc4'

method = 'POST'
url = 'https://api.twitter.com/1/direct_messages/new.json'

oauthParams = [
  ('oauth_consumer_key', 'kHvIYdQZIpx9ySnA0MMEiA'),
  ('oauth_signature_method', 'HMAC-SHA1'),
  ('oauth_timestamp', str(int(time()))),
  ('oauth_token', '618394533-7Sm4NOgy2PiRhG6GgEz90u7m7JCbQTO9zkW4JigS')]

message = mail.InboundEmailMessage(sys.stdin.read())

text = []

displayName, _ = email.utils.parseaddr(message.sender)
if displayName:
  text.append(displayName)

if message.subject:
  text.append(message.subject)

text += (body.decode() for _, body in message.bodies('text/plain'))

for _, addrSpec in email.utils.getaddresses((message.to,)):
  localPart = addrSpec.split('@', 1)[0]

  params = [
    ('screen_name', localPart),
    ('text', ' '.join(text)[:92])]

  #   The parameters collected in Section 3.4.1.3 are normalized into a
  #   single string as follows:
  #
  #   1.  First, the name and value of each parameter are encoded
  #       (Section 3.6).
  #
  #   2.  The parameters are sorted by name, using ascending byte value
  #       ordering.  If two or more parameters share the same name, they
  #       are sorted by their value.
  #
  #   3.  The name of each parameter is concatenated to its corresponding
  #       value using an "=" character (ASCII code 61) as a separator, even
  #       if the value is empty.
  #
  #   4.  The sorted name/value pairs are concatenated together into a
  #       single string by using an "&" character (ASCII code 38) as
  #       separator.

  normalParams = '&'.join(name + '=' + value for name, value in sorted([(percentEncode(name), percentEncode(value)) for (name, value) in params] + oauthParams))

  #   The signature base string is constructed by concatenating together,
  #   in order, the following HTTP request elements:
  #
  #   1.  The HTTP request method in uppercase.  For example: "HEAD",
  #       "GET", "POST", etc.  If the request uses a custom HTTP method, it
  #       MUST be encoded (Section 3.6).
  #
  #   2.  An "&" character (ASCII code 38).
  #
  #   3.  The base string URI from Section 3.4.1.2, after being encoded
  #       (Section 3.6).
  #
  #   4.  An "&" character (ASCII code 38).
  #
  #   5.  The request parameters as normalized in Section 3.4.1.3.2, after
  #       being encoded (Section 3.6).

  signatureBase = method + '&' + percentEncode(url) + '&' + percentEncode(normalParams)

  signature = base64.b64encode(hmac.new(key, signatureBase, hashlib.sha1).digest())

  #   Protocol parameters SHALL be included in the "Authorization" header
  #   field as follows:
  #
  #   1.  Parameter names and values are encoded per Parameter Encoding
  #       (Section 3.6).
  #
  #   2.  Each parameter's name is immediately followed by an "=" character
  #       (ASCII code 61), a """ character (ASCII code 34), the parameter
  #       value (MAY be empty), and another """ character (ASCII code 34).
  #
  #   3.  Parameters are separated by a "," character (ASCII code 44) and
  #       OPTIONAL linear whitespace per [RFC2617].
  #
  #   4.  The OPTIONAL "realm" parameter MAY be added and interpreted per
  #       [RFC2617] section 1.2.

  authorization = 'OAuth ' + ','.join(name + '="' + value + '"' for name, value in oauthParams + [('oauth_signature', percentEncode(signature))])

  result = urlfetch.fetch(url, urllib.urlencode(params), method, { 'Authorization': authorization })
