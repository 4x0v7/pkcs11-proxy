{
  "subject": {{ toJson .Subject }},
  "sans": {{ toJson .SANs }},
  "keyUsage": ["digitalSignature"],
  "extKeyUsage": ["serverAuth"],
  "extensions": [
    {
      "id": "1.7.4.4.6.3.3.4.4.8",
      "critical": false,
      "value": {{ asn1Enc (printf "utf8:%s" .Insecure.User.oidPolicy) | toJson }}
    }
  ]
}
