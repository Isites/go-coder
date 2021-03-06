// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.23.0
// 	protoc        v3.14.0
// source: testp3.proto

package p3optional

import (
	proto "github.com/golang/protobuf/proto"
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

// This is a compile-time assertion that a sufficiently up-to-date version
// of the legacy proto package is being used.
const _ = proto.ProtoPackageIsVersion4

type Status struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	IsShow *int32 `protobuf:"varint,1,opt,name=is_show,json=isShow,proto3,oneof" json:"is_show,omitempty"`
}

func (x *Status) Reset() {
	*x = Status{}
	if protoimpl.UnsafeEnabled {
		mi := &file_testp3_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Status) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Status) ProtoMessage() {}

func (x *Status) ProtoReflect() protoreflect.Message {
	mi := &file_testp3_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Status.ProtoReflect.Descriptor instead.
func (*Status) Descriptor() ([]byte, []int) {
	return file_testp3_proto_rawDescGZIP(), []int{0}
}

func (x *Status) GetIsShow() int32 {
	if x != nil && x.IsShow != nil {
		return *x.IsShow
	}
	return 0
}

type Test struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Bar int32   `protobuf:"varint,1,opt,name=bar,proto3" json:"bar,omitempty"`
	St  *Status `protobuf:"bytes,2,opt,name=st,proto3" json:"st,omitempty"`
}

func (x *Test) Reset() {
	*x = Test{}
	if protoimpl.UnsafeEnabled {
		mi := &file_testp3_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Test) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Test) ProtoMessage() {}

func (x *Test) ProtoReflect() protoreflect.Message {
	mi := &file_testp3_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Test.ProtoReflect.Descriptor instead.
func (*Test) Descriptor() ([]byte, []int) {
	return file_testp3_proto_rawDescGZIP(), []int{1}
}

func (x *Test) GetBar() int32 {
	if x != nil {
		return x.Bar
	}
	return 0
}

func (x *Test) GetSt() *Status {
	if x != nil {
		return x.St
	}
	return nil
}

var File_testp3_proto protoreflect.FileDescriptor

var file_testp3_proto_rawDesc = []byte{
	0x0a, 0x0c, 0x74, 0x65, 0x73, 0x74, 0x70, 0x33, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0a,
	0x70, 0x33, 0x6f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x61, 0x6c, 0x22, 0x32, 0x0a, 0x06, 0x53, 0x74,
	0x61, 0x74, 0x75, 0x73, 0x12, 0x1c, 0x0a, 0x07, 0x69, 0x73, 0x5f, 0x73, 0x68, 0x6f, 0x77, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x05, 0x48, 0x00, 0x52, 0x06, 0x69, 0x73, 0x53, 0x68, 0x6f, 0x77, 0x88,
	0x01, 0x01, 0x42, 0x0a, 0x0a, 0x08, 0x5f, 0x69, 0x73, 0x5f, 0x73, 0x68, 0x6f, 0x77, 0x22, 0x3c,
	0x0a, 0x04, 0x54, 0x65, 0x73, 0x74, 0x12, 0x10, 0x0a, 0x03, 0x62, 0x61, 0x72, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x05, 0x52, 0x03, 0x62, 0x61, 0x72, 0x12, 0x22, 0x0a, 0x02, 0x73, 0x74, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x12, 0x2e, 0x70, 0x33, 0x6f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x61,
	0x6c, 0x2e, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x52, 0x02, 0x73, 0x74, 0x42, 0x0e, 0x5a, 0x0c,
	0x2e, 0x3b, 0x70, 0x33, 0x6f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x61, 0x6c, 0x62, 0x06, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_testp3_proto_rawDescOnce sync.Once
	file_testp3_proto_rawDescData = file_testp3_proto_rawDesc
)

func file_testp3_proto_rawDescGZIP() []byte {
	file_testp3_proto_rawDescOnce.Do(func() {
		file_testp3_proto_rawDescData = protoimpl.X.CompressGZIP(file_testp3_proto_rawDescData)
	})
	return file_testp3_proto_rawDescData
}

var file_testp3_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_testp3_proto_goTypes = []interface{}{
	(*Status)(nil), // 0: p3optional.Status
	(*Test)(nil),   // 1: p3optional.Test
}
var file_testp3_proto_depIdxs = []int32{
	0, // 0: p3optional.Test.st:type_name -> p3optional.Status
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_testp3_proto_init() }
func file_testp3_proto_init() {
	if File_testp3_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_testp3_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Status); i {
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
		file_testp3_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Test); i {
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
	file_testp3_proto_msgTypes[0].OneofWrappers = []interface{}{}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_testp3_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_testp3_proto_goTypes,
		DependencyIndexes: file_testp3_proto_depIdxs,
		MessageInfos:      file_testp3_proto_msgTypes,
	}.Build()
	File_testp3_proto = out.File
	file_testp3_proto_rawDesc = nil
	file_testp3_proto_goTypes = nil
	file_testp3_proto_depIdxs = nil
}
