#include <catch/catch.hpp>
#include "TlsState.h"
#include "x509_certificate.h"

std::vector<uint8_t> privkey = { 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f };

std::vector<uint8_t> clientHelloBytes = {
0x16, 0x03, 0x01, 0x00, 0xca, 0x01, 0x00, 0x00, 0xc6, 0x03, 0x03, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff, 0x00, 0x06, 0x13, 0x01, 0x13, 0x02, 0x13, 0x03, 0x01, 0x00, 0x00, 0x77, 0x00, 0x00, 0x00, 0x18, 0x00, 0x16, 0x00, 0x00, 0x13, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x75, 0x6c, 0x66, 0x68, 0x65, 0x69, 0x6d, 0x2e, 0x6e, 0x65, 0x74, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x06, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x0d, 0x00, 0x14, 0x00, 0x12, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08, 0x05, 0x05, 0x01, 0x08, 0x06, 0x06, 0x01, 0x02, 0x01, 0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, 0x35, 0x80, 0x72, 0xd6, 0x36, 0x58, 0x80, 0xd1, 0xae, 0xea, 0x32, 0x9a, 0xdf, 0x91, 0x21, 0x38, 0x38, 0x51, 0xed, 0x21, 0xa2, 0x8e, 0x3b, 0x75, 0xe9, 0x65, 0xd0, 0xd2, 0xcd, 0x16, 0x62, 0x54, 0x00, 0x2d, 0x00, 0x02, 0x01, 0x01, 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04, 
  };

std::vector<uint8_t> serverHelloAndStuff = {
0x16, 0x03, 0x03, 0x00, 0x7a, 0x02, 0x00, 0x00, 0x76, 0x03, 0x03, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x20, 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff, 0x13, 0x01, 0x00, 0x00, 0x2e, 0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, 0x9f, 0xd7, 0xad, 0x6d, 0xcf, 0xf4, 0x29, 0x8d, 0xd3, 0xf9, 0x6d, 0x5b, 0x1b, 0x2a, 0xf9, 0x10, 0xa0, 0x53, 0x5b, 0x14, 0x88, 0xd7, 0xf8, 0xfa, 0xbb, 0x34, 0x9a, 0x98, 0x28, 0x80, 0xb6, 0x15, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04, 
0x14, 0x03, 0x03, 0x00, 0x01, 0x01, 
0x17, 0x03, 0x03, 0x04, 0x75, 0xda, 0x1e, 0xc2, 0xd7, 0xbd, 0xa8, 0xeb, 0xf7, 0x3e, 0xdd, 0x50, 0x10, 0xfb, 0xa8, 0x08, 0x9f, 0xd4, 0x26, 0xb0, 0xea, 0x1e, 0xa4, 0xd8, 0x8d, 0x07, 0x4f, 0xfe, 0xa8, 0xa9, 0x87, 0x3a, 0xf5, 0xf5, 0x02, 0x26, 0x1e, 0x34, 0xb1, 0x56, 0x33, 0x43, 0xe9, 0xbe, 0xb6, 0x13, 0x2e, 0x7e, 0x83, 0x6d, 0x65, 0xdb, 0x6d, 0xcf, 0x00, 0xbc, 0x40, 0x19, 0x35, 0xae, 0x36, 0x9c, 0x44, 0x0d, 0x67, 0xaf, 0x71, 0x9e, 0xc0, 0x3b, 0x98, 0x4c, 0x45, 0x21, 0xb9, 0x05, 0xd5, 0x8b, 0xa2, 0x19, 0x7c, 0x45, 0xc4, 0xf7, 0x73, 0xbd, 0x9d, 0xd1, 0x21, 0xb4, 0xd2, 0xd4, 0xe6, 0xad, 0xff, 0xfa, 0x27, 0xc2, 0xa8, 0x1a, 0x99, 0xa8, 0xef, 0xe8, 0x56, 0xc3, 0x5e, 0xe0, 0x8b, 0x71, 0xb3, 0xe4, 0x41, 0xbb, 0xec, 0xaa, 0x65, 0xfe, 0x72, 0x08, 0x15, 0xca, 0xb5, 0x8d, 0xb3, 0xef, 0xa8, 0xd1, 0xe5, 0xb7, 0x1c, 0x58, 0xe8, 0xd1, 0xfd, 0xb6, 0xb2, 0x1b, 0xfc, 0x66, 0xa9, 0x86, 0x5f, 0x85, 0x2c, 0x1b, 0x4b, 0x64, 0x0e, 0x94, 0xbd, 0x90, 0x84, 0x69, 0xe7, 0x15, 0x1f, 0x9b, 0xbc, 0xa3, 0xce, 0x53, 0x22, 0x4a, 0x27, 0x06, 0x2c, 0xeb, 0x24, 0x0a, 0x10, 0x5b, 0xd3, 0x13, 0x2d, 0xc1, 0x85, 0x44, 0x47, 0x77, 0x94, 0xc3, 0x73, 0xbc, 0x0f, 0xb5, 0xa2, 0x67, 0x88, 0x5c, 0x85, 0x7d, 0x4c, 0xcb, 0x4d, 0x31, 0x74, 0x2b, 0x7a, 0x29, 0x62, 0x40, 0x29, 0xfd, 0x05, 0x94, 0x0d, 0xe3, 0xf9, 0xf9, 0xb6, 0xe0, 0xa9, 0xa2, 0x37, 0x67, 0x2b, 0xc6, 0x24, 0xba, 0x28, 0x93, 0xa2, 0x17, 0x09, 0x83, 0x3c, 0x52, 0x76, 0xd4, 0x13, 0x63, 0x1b, 0xdd, 0xe6, 0xae, 0x70, 0x08, 0xc6, 0x97, 0xa8, 0xef, 0x42, 0x8a, 0x79, 0xdb, 0xf6, 0xe8, 0xbb, 0xeb, 0x47, 0xc4, 0xe4, 0x08, 0xef, 0x65, 0x6d, 0x9d, 0xc1, 0x9b, 0x8b, 0x5d, 0x49, 0xbc, 0x09, 0x1e, 0x21, 0x77, 0x35, 0x75, 0x94, 0xc8, 0xac, 0xd4, 0x1c, 0x10, 0x1c, 0x77, 0x50, 0xcb, 0x11, 0xb5, 0xbe, 0x6a, 0x19, 0x4b, 0x8f, 0x87, 0x70, 0x88, 0xc9, 0x82, 0x8e, 0x35, 0x07, 0xda, 0xda, 0x17, 0xbb, 0x14, 0xbb, 0x2c, 0x73, 0x89, 0x03, 0xc7, 0xaa, 0xb4, 0x0c, 0x54, 0x5c, 0x46, 0xaa, 0x53, 0x82, 0x3b, 0x12, 0x01, 0x81, 0xa1, 0x6c, 0xe9, 0x28, 0x76, 0x28, 0x8c, 0x4a, 0xcd, 0x81, 0x5b, 0x23, 0x3d, 0x96, 0xbb, 0x57, 0x2b, 0x16, 0x2e, 0xc1, 0xb9, 0xd7, 0x12, 0xf2, 0xc3, 0x96, 0x6c, 0xaa, 0xc9, 0xcf, 0x17, 0x4f, 0x3a, 0xed, 0xfe, 0xc4, 0xd1, 0x9f, 0xf9, 0xa8, 0x7f, 0x8e, 0x21, 0xe8, 0xe1, 0xa9, 0x78, 0x9b, 0x49, 0x0b, 0xa0, 0x5f, 0x1d, 0xeb, 0xd2, 0x17, 0x32, 0xfb, 0x2e, 0x15, 0xa0, 0x17, 0xc4, 0x75, 0xc4, 0xfd, 0x00, 0xbe, 0x04, 0x21, 0x86, 0xdc, 0x29, 0xe6, 0x8b, 0xb7, 0xec, 0xe1, 0x92, 0x43, 0x8f, 0x3b, 0x0c, 0x5e, 0xf8, 0xe4, 0xa5, 0x35, 0x83, 0xa0, 0x19, 0x43, 0xcf, 0x84, 0xbb, 0xa5, 0x84, 0x21, 0x73, 0xa6, 0xb3, 0xa7, 0x28, 0x95, 0x66, 0x68, 0x7c, 0x30, 0x18, 0xf7, 0x64, 0xab, 0x18, 0x10, 0x31, 0x69, 0x91, 0x93, 0x28, 0x71, 0x3c, 0x3b, 0xd4, 0x63, 0xd3, 0x39, 0x8a, 0x1f, 0xeb, 0x8e, 0x68, 0xe4, 0x4c, 0xfe, 0x48, 0x2f, 0x72, 0x84, 0x7f, 0x46, 0xc8, 0x0e, 0x6c, 0xc7, 0xf6, 0xcc, 0xf1, 0x79, 0xf4, 0x82, 0xc8, 0x88, 0x59, 0x4e, 0x76, 0x27, 0x66, 0x53, 0xb4, 0x83, 0x98, 0xa2, 0x6c, 0x7c, 0x9e, 0x42, 0x0c, 0xb6, 0xc1, 0xd3, 0xbc, 0x76, 0x46, 0xf3, 0x3b, 0xb8, 0x32, 0xbf, 0xba, 0x98, 0x48, 0x9c, 0xad, 0xfb, 0xd5, 0x5d, 0xd8, 0xb2, 0xc5, 0x76, 0x87, 0xa4, 0x7a, 0xcb, 0xa4, 0xab, 0x39, 0x01, 0x52, 0xd8, 0xfb, 0xb3, 0xf2, 0x03, 0x27, 0xd8, 0x24, 0xb2, 0x84, 0xd2, 0x88, 0xfb, 0x01, 0x52, 0xe4, 0x9f, 0xc4, 0x46, 0x78, 0xae, 0xd4, 0xd3, 0xf0, 0x85, 0xb7, 0xc5, 0x5d, 0xe7, 0x7b, 0xd4, 0x5a, 0xf8, 0x12, 0xfc, 0x37, 0x94, 0x4a, 0xd2, 0x45, 0x4f, 0x99, 0xfb, 0xb3, 0x4a, 0x58, 0x3b, 0xf1, 0x6b, 0x67, 0x65, 0x9e, 0x6f, 0x21, 0x6d, 0x34, 0xb1, 0xd7, 0x9b, 0x1b, 0x4d, 0xec, 0xc0, 0x98, 0xa4, 0x42, 0x07, 0xe1, 0xc5, 0xfe, 0xeb, 0x6c, 0xe3, 0x0a, 0xcc, 0x2c, 0xf7, 0xe2, 0xb1, 0x34, 0x49, 0x0b, 0x44, 0x27, 0x44, 0x77, 0x2d, 0x18, 0x4e, 0x59, 0x03, 0x8a, 0xa5, 0x17, 0xa9, 0x71, 0x54, 0x18, 0x1e, 0x4d, 0xfd, 0x94, 0xfe, 0x72, 0xa5, 0xa4, 0xca, 0x2e, 0x7e, 0x22, 0xbc, 0xe7, 0x33, 0xd0, 0x3e, 0x7d, 0x93, 0x19, 0x71, 0x0b, 0xef, 0xbc, 0x30, 0xd7, 0x82, 0x6b, 0x72, 0x85, 0x19, 0xba, 0x74, 0x69, 0x0e, 0x4f, 0x90, 0x65, 0x87, 0xa0, 0x38, 0x28, 0x95, 0xb9, 0x0d, 0x82, 0xed, 0x3e, 0x35, 0x7f, 0xaf, 0x8e, 0x59, 0xac, 0xa8, 0x5f, 0xd2, 0x06, 0x3a, 0xb5, 0x92, 0xd8, 0x3d, 0x24, 0x5a, 0x91, 0x9e, 0xa5, 0x3c, 0x50, 0x1b, 0x9a, 0xcc, 0xd2, 0xa1, 0xed, 0x95, 0x1f, 0x43, 0xc0, 0x49, 0xab, 0x9d, 0x25, 0xc7, 0xf1, 0xb7, 0x0a, 0xe4, 0xf9, 0x42, 0xed, 0xb1, 0xf3, 0x11, 0xf7, 0x41, 0x78, 0x33, 0x06, 0x22, 0x45, 0xb4, 0x29, 0xd4, 0xf0, 0x13, 0xae, 0x90, 0x19, 0xff, 0x52, 0x04, 0x4c, 0x97, 0xc7, 0x3b, 0x88, 0x82, 0xcf, 0x03, 0x95, 0x5c, 0x73, 0x9f, 0x87, 0x4a, 0x02, 0x96, 0x37, 0xc0, 0xf0, 0x60, 0x71, 0x00, 0xe3, 0x07, 0x0f, 0x40, 0x8d, 0x08, 0x2a, 0xa7, 0xa2, 0xab, 0xf1, 0x3e, 0x73, 0xbd, 0x1e, 0x25, 0x2c, 0x22, 0x8a, 0xba, 0x7a, 0x9c, 0x1f, 0x07, 0x5b, 0xc4, 0x39, 0x57, 0x1b, 0x35, 0x93, 0x2f, 0x5c, 0x91, 0x2c, 0xb0, 0xb3, 0x8d, 0xa1, 0xc9, 0x5e, 0x64, 0xfc, 0xf9, 0xbf, 0xec, 0x0b, 0x9b, 0x0d, 0xd8, 0xf0, 0x42, 0xfd, 0xf0, 0x5e, 0x50, 0x58, 0x29, 0x9e, 0x96, 0xe4, 0x18, 0x50, 0x74, 0x91, 0x9d, 0x90, 0xb7, 0xb3, 0xb0, 0xa9, 0x7e, 0x22, 0x42, 0xca, 0x08, 0xcd, 0x99, 0xc9, 0xec, 0xb1, 0x2f, 0xc4, 0x9a, 0xdb, 0x2b, 0x25, 0x72, 0x40, 0xcc, 0x38, 0x78, 0x02, 0xf0, 0x0e, 0x0e, 0x49, 0x95, 0x26, 0x63, 0xea, 0x27, 0x84, 0x08, 0x70, 0x9b, 0xce, 0x5b, 0x36, 0x3c, 0x03, 0x60, 0x93, 0xd7, 0xa0, 0x5d, 0x44, 0x0c, 0x9e, 0x7a, 0x7a, 0xbb, 0x3d, 0x71, 0xeb, 0xb4, 0xd1, 0x0b, 0xfc, 0x77, 0x81, 0xbc, 0xd6, 0x6f, 0x79, 0x32, 0x2c, 0x18, 0x26, 0x2d, 0xfc, 0x2d, 0xcc, 0xf3, 0xe5, 0xf1, 0xea, 0x98, 0xbe, 0xa3, 0xca, 0xae, 0x8a, 0x83, 0x70, 0x63, 0x12, 0x76, 0x44, 0x23, 0xa6, 0x92, 0xae, 0x0c, 0x1e, 0x2e, 0x23, 0xb0, 0x16, 0x86, 0x5f, 0xfb, 0x12, 0x5b, 0x22, 0x38, 0x57, 0x54, 0x7a, 0xc7, 0xe2, 0x46, 0x84, 0x33, 0xb5, 0x26, 0x98, 0x43, 0xab, 0xba, 0xbb, 0xe9, 0xf6, 0xf4, 0x38, 0xd7, 0xe3, 0x87, 0xe3, 0x61, 0x7a, 0x21, 0x9f, 0x62, 0x54, 0x0e, 0x73, 0x43, 0xe1, 0xbb, 0xf4, 0x93, 0x55, 0xfb, 0x5a, 0x19, 0x38, 0x04, 0x84, 0x39, 0xcb, 0xa5, 0xce, 0xe8, 0x19, 0x19, 0x9b, 0x2b, 0x5c, 0x39, 0xfd, 0x35, 0x1a, 0xa2, 0x74, 0x53, 0x6a, 0xad, 0xb6, 0x82, 0xb5, 0x78, 0x94, 0x3f, 0x0c, 0xcf, 0x48, 0xe4, 0xec, 0x7d, 0xdc, 0x93, 0x8e, 0x2f, 0xd0, 0x1a, 0xcf, 0xaa, 0x1e, 0x72, 0x17, 0xf7, 0xb3, 0x89, 0x28, 0x5c, 0x0d, 0xfd, 0x31, 0xa1, 0x54, 0x5e, 0xd3, 0xa8, 0x5f, 0xac, 0x8e, 0xb9, 0xda, 0xb6, 0xee, 0x82, 0x6a, 0xf9, 0x0f, 0x9e, 0x1e, 0xe5, 0xd5, 0x55, 0xdd, 0x1c, 0x05, 0xae, 0xc0, 0x77, 0xf7, 0xc8, 0x03, 0xcb, 0xc2, 0xf1, 0xcf, 0x98, 0x39, 0x3f, 0x0f, 0x37, 0x83, 0x8f, 0xfe, 0xa3, 0x72, 0xff, 0x70, 0x88, 0x86, 0xb0, 0x59, 0x34, 0xe1, 0xa6, 0x45, 0x12, 0xde, 0x14, 0x46, 0x08, 0x86, 0x4a, 0x88, 0xa5, 0xc3, 0xa1, 0x73, 0xfd, 0xcf, 0xdf, 0x57, 0x25, 0xda, 0x91, 0x6e, 0xd5, 0x07, 0xe4, 0xca, 0xec, 0x87, 0x87, 0xbe, 0xfb, 0x91, 0xe3, 0xec, 0x9b, 0x22, 0x2f, 0xa0, 0x9f, 0x37, 0x4b, 0xd9, 0x68, 0x81, 0xac, 0x2d, 0xdd, 0x1f, 0x88, 0x5d, 0x42, 0xea, 0x58, 0x4c, 0xe0, 0x8b, 0x0e, 0x45, 0x5a, 0x35, 0x0a, 0xe5, 0x4d, 0x76, 0x34, 0x9a, 0xa6, 0x8c, 0x71, 0xae, 
};

std::vector<uint8_t> clientFinished = {
  0x17, 0x03, 0x03, 0x00, 0x35, 0x71, 0x55, 0xdf, 0xf4, 0x74, 0x1b, 0xdf, 0xc0, 0xc4, 0x3a, 0x1d, 0xe0, 0xb0, 0x11, 0x33, 0xac, 0x19, 0x74, 0xed, 0xc8, 0x8e, 0x70, 0x91, 0xc3, 0xff, 0x1e, 0x26, 0x60, 0xcd, 0x71, 0x92, 0x83, 0xba, 0x40, 0xf7, 0xc1, 0x0b, 0x54, 0x35, 0xd4, 0xeb, 0x22, 0xd0, 0x53, 0x6c, 0x80, 0xc9, 0x32, 0xe2, 0xf3, 0xc9, 0x60, 0x83, 
};

std::string ulfheimroot = 
"-----BEGIN CERTIFICATE-----\n"
"MIIDATCCAemgAwIBAgIBATANBgkqhkiG9w0BAQsFADAiMQswCQYDVQQGEwJVUzET\n"
"MBEGA1UEChMKRXhhbXBsZSBDQTAeFw0xODEwMDUwMTM3NTVaFw0yODEwMDUwMTM3\n"
"NTVaMCIxCzAJBgNVBAYTAlVTMRMwEQYDVQQKEwpFeGFtcGxlIENBMIIBIjANBgkq\n"
"hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw3KoKthct8kUhCr6IXt303X11BWDTVOD\n"
"Q82Y9ltNa3INXgUdg3pbFJc017d2bYsfxQ3ekcs/28P/lCn+wAc1IcJMTV0m5om3\n"
"l7khTZevI9PwIjtWOPnU1M4jlDelp+i0QxIT/vA02pM4xF5SpjMlBnhBxmKepxBY\n"
"RyKkCJqAKbTGYTCFvEa5Lg9lvEtROrhZ3EgnicyRDQBxeSfLxK3zZa++0TZOWEQ0\n"
"e5HfdfHdmBotiQ/LEQ8lbSnZqLRAzGhcoIVemJ8XcYIDLhYoTk2VYbfkyy0QGhDm\n"
"qBCIXFvWzrLm5/Ux+TUXpC3HQlEzvDTJLo/1/x4wKDVMcOYtVdQ5XwIDAQABo0Iw\n"
"QDAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUiU/e\n"
"W8xp4lLPPqMA37GXuB3hwUYwDQYJKoZIhvcNAQELBQADggEBAGo5sILExEsBO7If\n"
"siOtHdz0HIi55hUDYZbkx0erO/+LHaeM3ufJoYMW+gQ+3xmJ74bqNsbibPbi2pzQ\n"
"wxd5+5K9BYsqY4XTdLxD1F8iEELFg04I+JB4tmzGpeTXEFY/lBNNRHbsKw7bTh+c\n"
"CkMyNfHDshAQOUJ5fTpiNF2MF96LRK1XwtLSpaffnLY1bvdKLMU0h6yKUpYaOizw\n"
"1H+XNuC6/vjPo7q92XiuCGgfyrfWap/U6DH1dWUrk+avvfJ7nzotgjx7ddssW4nP\n"
"z0Xbzt6dvZppaRceRTFIUyhES33qawZn1zLNdPBaprfkX3crzU7kzNpRnd+BaMBO\n"
"irkvU+w=\n"
"-----END CERTIFICATE-----\n";

TEST_CASE("Full ULFHEIM.NET TLS1.3 connection", "[TLS]") {
  std::span<uint8_t> cert((uint8_t*)ulfheimroot.data(), ulfheimroot.size());
  Truststore::Instance().addCertificate(parseCertificate(cert, CertificateFormat::Pem));

  TlsState state("example.ulfheim.net", 1550000000);
  state.privkey = bignum<256>(privkey);
  std::vector<uint8_t> data;
  data = state.startupExchange(data);
  REQUIRE(data == clientHelloBytes);
  data = state.startupExchange(serverHelloAndStuff);
  REQUIRE(data == clientFinished);


}

