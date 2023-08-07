// SPDX-License-Identifier: MIT

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.30.0
// 	protoc        v4.23.4
// source: macvlan.proto

package macvlan

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type MacvlanLinkEntry struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Mode  *uint32 `protobuf:"varint,1,req,name=mode" json:"mode,omitempty"`
	Flags *uint32 `protobuf:"varint,2,opt,name=flags" json:"flags,omitempty"`
}

func (x *MacvlanLinkEntry) Reset() {
	*x = MacvlanLinkEntry{}
	if protoimpl.UnsafeEnabled {
		mi := &file_macvlan_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *MacvlanLinkEntry) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*MacvlanLinkEntry) ProtoMessage() {}

func (x *MacvlanLinkEntry) ProtoReflect() protoreflect.Message {
	mi := &file_macvlan_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use MacvlanLinkEntry.ProtoReflect.Descriptor instead.
func (*MacvlanLinkEntry) Descriptor() ([]byte, []int) {
	return file_macvlan_proto_rawDescGZIP(), []int{0}
}

func (x *MacvlanLinkEntry) GetMode() uint32 {
	if x != nil && x.Mode != nil {
		return *x.Mode
	}
	return 0
}

func (x *MacvlanLinkEntry) GetFlags() uint32 {
	if x != nil && x.Flags != nil {
		return *x.Flags
	}
	return 0
}

var File_macvlan_proto protoreflect.FileDescriptor

var file_macvlan_proto_rawDesc = []byte{
	0x0a, 0x0d, 0x6d, 0x61, 0x63, 0x76, 0x6c, 0x61, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22,
	0x3e, 0x0a, 0x12, 0x6d, 0x61, 0x63, 0x76, 0x6c, 0x61, 0x6e, 0x5f, 0x6c, 0x69, 0x6e, 0x6b, 0x5f,
	0x65, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x12, 0x0a, 0x04, 0x6d, 0x6f, 0x64, 0x65, 0x18, 0x01, 0x20,
	0x02, 0x28, 0x0d, 0x52, 0x04, 0x6d, 0x6f, 0x64, 0x65, 0x12, 0x14, 0x0a, 0x05, 0x66, 0x6c, 0x61,
	0x67, 0x73, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x05, 0x66, 0x6c, 0x61, 0x67, 0x73,
}

var (
	file_macvlan_proto_rawDescOnce sync.Once
	file_macvlan_proto_rawDescData = file_macvlan_proto_rawDesc
)

func file_macvlan_proto_rawDescGZIP() []byte {
	file_macvlan_proto_rawDescOnce.Do(func() {
		file_macvlan_proto_rawDescData = protoimpl.X.CompressGZIP(file_macvlan_proto_rawDescData)
	})
	return file_macvlan_proto_rawDescData
}

var file_macvlan_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_macvlan_proto_goTypes = []interface{}{
	(*MacvlanLinkEntry)(nil), // 0: macvlan_link_entry
}
var file_macvlan_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_macvlan_proto_init() }
func file_macvlan_proto_init() {
	if File_macvlan_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_macvlan_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*MacvlanLinkEntry); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_macvlan_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_macvlan_proto_goTypes,
		DependencyIndexes: file_macvlan_proto_depIdxs,
		MessageInfos:      file_macvlan_proto_msgTypes,
	}.Build()
	File_macvlan_proto = out.File
	file_macvlan_proto_rawDesc = nil
	file_macvlan_proto_goTypes = nil
	file_macvlan_proto_depIdxs = nil
}