// Code generated by protoc-gen-go.
// source: github.com/ashwinsr/auctions/millionaire/millionaire.proto
// DO NOT EDIT!

/*
Package main is a generated protocol buffer package.

It is generated from these files:
	github.com/ashwinsr/auctions/millionaire/millionaire.proto

It has these top-level messages:
	AlphaBeta
	MixedOutput
	RandomizedOutput
	DecryptionInfo
*/
package main

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"
import common_pb "github.com/ashwinsr/auctions/common_pb"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

// TODO millionaire specific
type AlphaBeta struct {
	Alphas [][]byte                    `protobuf:"bytes,1,rep,name=alphas,proto3" json:"alphas,omitempty"`
	Betas  [][]byte                    `protobuf:"bytes,2,rep,name=betas,proto3" json:"betas,omitempty"`
	Proofs []*common_pb.EqualsOneOfTwo `protobuf:"bytes,3,rep,name=proofs" json:"proofs,omitempty"`
}

func (m *AlphaBeta) Reset()                    { *m = AlphaBeta{} }
func (m *AlphaBeta) String() string            { return proto.CompactTextString(m) }
func (*AlphaBeta) ProtoMessage()               {}
func (*AlphaBeta) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

func (m *AlphaBeta) GetProofs() []*common_pb.EqualsOneOfTwo {
	if m != nil {
		return m.Proofs
	}
	return nil
}

// TODO millionaire specific
type MixedOutput struct {
	Gammas [][]byte                     `protobuf:"bytes,1,rep,name=gammas,proto3" json:"gammas,omitempty"`
	Deltas [][]byte                     `protobuf:"bytes,2,rep,name=deltas,proto3" json:"deltas,omitempty"`
	Proof  *common_pb.VerifiableShuffle `protobuf:"bytes,3,opt,name=proof" json:"proof,omitempty"`
}

func (m *MixedOutput) Reset()                    { *m = MixedOutput{} }
func (m *MixedOutput) String() string            { return proto.CompactTextString(m) }
func (*MixedOutput) ProtoMessage()               {}
func (*MixedOutput) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{1} }

func (m *MixedOutput) GetProof() *common_pb.VerifiableShuffle {
	if m != nil {
		return m.Proof
	}
	return nil
}

// TODO millionaire specific
type RandomizedOutput struct {
	Gammas [][]byte                         `protobuf:"bytes,1,rep,name=gammas,proto3" json:"gammas,omitempty"`
	Deltas [][]byte                         `protobuf:"bytes,2,rep,name=deltas,proto3" json:"deltas,omitempty"`
	Proofs []*common_pb.DiscreteLogEquality `protobuf:"bytes,3,rep,name=proofs" json:"proofs,omitempty"`
}

func (m *RandomizedOutput) Reset()                    { *m = RandomizedOutput{} }
func (m *RandomizedOutput) String() string            { return proto.CompactTextString(m) }
func (*RandomizedOutput) ProtoMessage()               {}
func (*RandomizedOutput) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{2} }

func (m *RandomizedOutput) GetProofs() []*common_pb.DiscreteLogEquality {
	if m != nil {
		return m.Proofs
	}
	return nil
}

// TODO millionaire specific
type DecryptionInfo struct {
	Phis   [][]byte                         `protobuf:"bytes,1,rep,name=phis,proto3" json:"phis,omitempty"`
	Proofs []*common_pb.DiscreteLogEquality `protobuf:"bytes,2,rep,name=proofs" json:"proofs,omitempty"`
}

func (m *DecryptionInfo) Reset()                    { *m = DecryptionInfo{} }
func (m *DecryptionInfo) String() string            { return proto.CompactTextString(m) }
func (*DecryptionInfo) ProtoMessage()               {}
func (*DecryptionInfo) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{3} }

func (m *DecryptionInfo) GetProofs() []*common_pb.DiscreteLogEquality {
	if m != nil {
		return m.Proofs
	}
	return nil
}

func init() {
	proto.RegisterType((*AlphaBeta)(nil), "main.AlphaBeta")
	proto.RegisterType((*MixedOutput)(nil), "main.MixedOutput")
	proto.RegisterType((*RandomizedOutput)(nil), "main.RandomizedOutput")
	proto.RegisterType((*DecryptionInfo)(nil), "main.DecryptionInfo")
}

func init() {
	proto.RegisterFile("github.com/ashwinsr/auctions/millionaire/millionaire.proto", fileDescriptor0)
}

var fileDescriptor0 = []byte{
	// 310 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x09, 0x6e, 0x88, 0x02, 0xff, 0x9c, 0x91, 0xcf, 0x4b, 0xfb, 0x40,
	0x10, 0xc5, 0x69, 0xd3, 0x16, 0xbe, 0xdb, 0x2f, 0x22, 0x8b, 0x48, 0x14, 0x91, 0xd2, 0x53, 0x4f,
	0x29, 0xb6, 0xe0, 0xc1, 0x9b, 0x52, 0x0f, 0x82, 0x52, 0x88, 0xe2, 0x49, 0x90, 0x4d, 0xba, 0x49,
	0x06, 0x76, 0x77, 0xb6, 0xfb, 0x83, 0xda, 0xfe, 0xf5, 0x92, 0x1f, 0xb6, 0xc1, 0x83, 0xa0, 0xb7,
	0xf7, 0x86, 0x99, 0xf7, 0xe1, 0x31, 0xe4, 0x26, 0x07, 0x57, 0xf8, 0x24, 0x4a, 0x51, 0x4e, 0x99,
	0x2d, 0x36, 0xa0, 0xac, 0x99, 0x32, 0x9f, 0x3a, 0x40, 0x65, 0xa7, 0x12, 0x84, 0x00, 0x54, 0x0c,
	0x0c, 0x6f, 0xeb, 0x48, 0x1b, 0x74, 0x48, 0x7b, 0x92, 0x81, 0x3a, 0x9f, 0xff, 0x98, 0x90, 0xa2,
	0x94, 0xa8, 0xde, 0x75, 0xd2, 0xa8, 0xfa, 0x74, 0x2c, 0xc8, 0xbf, 0x5b, 0xa1, 0x0b, 0x76, 0xc7,
	0x1d, 0xa3, 0xa7, 0x64, 0xc0, 0x4a, 0x63, 0xc3, 0xce, 0x28, 0x98, 0xfc, 0x8f, 0x1b, 0x47, 0x4f,
	0x48, 0x3f, 0xe1, 0x8e, 0xd9, 0xb0, 0x5b, 0x8d, 0x6b, 0x43, 0xaf, 0xc8, 0x40, 0x1b, 0xc4, 0xcc,
	0x86, 0xc1, 0x28, 0x98, 0x0c, 0x67, 0x67, 0xd1, 0x9e, 0x11, 0xdd, 0xaf, 0x3d, 0x13, 0x76, 0xa9,
	0xf8, 0x32, 0x7b, 0xd9, 0x60, 0xdc, 0x2c, 0x8e, 0xd7, 0x64, 0xf8, 0x04, 0x1f, 0x7c, 0xb5, 0xf4,
	0x4e, 0x7b, 0x57, 0xf2, 0x72, 0x26, 0xe5, 0x81, 0x57, 0xbb, 0x72, 0xbe, 0xe2, 0xe2, 0x00, 0x6c,
	0x1c, 0x9d, 0x91, 0x7e, 0x15, 0x14, 0x06, 0xa3, 0xce, 0x64, 0x38, 0xbb, 0x68, 0x01, 0x5f, 0xb9,
	0x81, 0x0c, 0x58, 0x22, 0xf8, 0x73, 0xe1, 0xb3, 0x4c, 0xf0, 0xb8, 0x5e, 0x1d, 0xef, 0xc8, 0x71,
	0xcc, 0xd4, 0x0a, 0x25, 0xec, 0xfe, 0xcc, 0xbd, 0xfe, 0xd6, 0xf4, 0xb2, 0x05, 0x5e, 0x80, 0x4d,
	0x0d, 0x77, 0xfc, 0x11, 0xf3, 0xaa, 0x34, 0xb8, 0xed, 0xbe, 0xee, 0x1b, 0x39, 0x5a, 0xf0, 0xd4,
	0x6c, 0x75, 0xf9, 0x82, 0x07, 0x95, 0x21, 0xa5, 0xa4, 0xa7, 0x0b, 0xf8, 0xe2, 0x56, 0xba, 0x95,
	0xde, 0xfd, 0x4d, 0x7a, 0x32, 0xa8, 0x3e, 0x38, 0xff, 0x0c, 0x00, 0x00, 0xff, 0xff, 0x85, 0x3e,
	0xe5, 0x38, 0x3a, 0x02, 0x00, 0x00,
}
