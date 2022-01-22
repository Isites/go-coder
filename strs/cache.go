package main

import (
	"sync"
	"time"
)

type cacheItem struct {
	data      interface{}
	expiredAt int64
}

// IsExpired 判断缓存内容是否到期
func (c *cacheItem) IsExpired() bool {
	return c.expiredAt > 0 && time.Now().Unix() >= c.expiredAt
}

func (c *cacheItem) Data() interface{} {
	return c.data
}

var (
	cacheMap sync.Map
)

// Set 设置缓存
func Set(key string, val interface{}, expiredAt int64) {
	cv := &cacheItem{val, expiredAt}
	cacheMap.Store(key, cv)
}

// Get 得到缓存中的值
func Get(key string) (interface{}, bool) {
	// 不存在缓存
	cv, isExists := cacheMap.Load(key)
	if !isExists {
		return nil, false
	}
	// 缓存不正确
	citem, ok := cv.(*cacheItem)
	if !ok {
		return nil, false
	}
	// 读数据时删除缓存
	if citem.IsExpired() {
		cacheMap.Delete(key)
		return nil, false
	}
	// 最后返回结果
	return citem.Data(), true
}
