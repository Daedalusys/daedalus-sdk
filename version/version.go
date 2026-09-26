// Package version 提供版本与模块路径常量,避免散落各处造成漂移。
package version

// Version 是语义化版本号,由发布流程统一递增。
const Version = "0.1.0"

// ModulePath 是模块导入路径,也是所有内部包导入路径的固定前缀。
const ModulePath = "github.com/Daedalusys/daedalus-core"
