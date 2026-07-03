export const WORKLOAD_API_PROTO = `
syntax = "proto3";

service SpiffeWorkloadAPI {
  rpc FetchX509SVID(X509SVIDRequest) returns (stream X509SVIDResponse);
  rpc FetchX509Bundles(X509BundlesRequest) returns (stream X509BundlesResponse);
}

message X509SVIDRequest {}

message X509SVIDResponse {
  repeated X509SVID svids = 1;
  repeated bytes crl = 2;
  map<string, bytes> federated_bundles = 3;
}

message X509SVID {
  string spiffe_id = 1;
  bytes x509_svid = 2;
  bytes x509_svid_key = 3;
  bytes bundle = 4;
  string hint = 5;
}

message X509BundlesRequest {}

message X509BundlesResponse {
  repeated bytes crl = 1;
  map<string, bytes> bundles = 2;
}
`;