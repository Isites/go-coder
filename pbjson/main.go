package main

import (
	"encoding/json"
	"fmt"

	"github.com/Isites/go-coder/pbjson/p3p2"

	"github.com/Isites/go-coder/pbjson/p3optional"

	"github.com/Isites/go-coder/pbjson/wrapper"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/Isites/go-coder/pbjson/oneof"
)

func main() {
	// oneof to json
	ot1 := oneof.Test{
		Bar: 1,
		St: &oneof.Status{
			Show: &oneof.Status_IsShow{
				IsShow: 1,
			},
		},
	}
	bts, err := json.Marshal(ot1)
	fmt.Println(string(bts), err)
	// json to oneof failed
	jsonStr := `{"bar":1,"st":{"Show":{"is_show":1}}}`
	var ot2 oneof.Test
	fmt.Println(json.Unmarshal([]byte(jsonStr), &ot2))

	// wrapper to json, 注意：笔者实践得知gogoproto不支持此方法
	wra1 := wrapper.Test{
		Bar: 1,
		St: &wrapper.Status{
			IsShow: wrapperspb.Int32(1),
		},
	}
	bts, err = json.Marshal(wra1)
	fmt.Println(string(bts), err)
	jsonStr = `{"bar":1,"st":{"is_show":{"value":1}}}`
	// 可正常转json
	var wra2 wrapper.Test
	fmt.Println(json.Unmarshal([]byte(jsonStr), &wra2))

	// p3optional to json 注意：笔者实践得知gogoproto不支持此方法
	var isShow int32 = 1
	p3o1 := p3optional.Test{
		Bar: 1,
		St: &p3optional.Status{
			IsShow: &isShow,
		},
	}
	bts, err = json.Marshal(p3o1)
	fmt.Println(string(bts), err)
	var p3o2 p3optional.Test
	jsonStr = `{"bar":1,"st":{"is_show":1}}`
	fmt.Println(json.Unmarshal([]byte(jsonStr), &p3o2))

	// p3p2 to json
	p3p21 := p3p2.Test{
		Bar: 1,
		St: &p3p2.Status{
			IsShow: &isShow,
		},
	}
	bts, err = json.Marshal(p3p21)
	fmt.Println(string(bts), err)
	var p3p22 p3p2.Test
	jsonStr = `{"custom_tag":1,"st":{"is_show":1}}`
	fmt.Println(json.Unmarshal([]byte(jsonStr), &p3p22))
}
