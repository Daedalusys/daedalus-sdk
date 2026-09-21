// Package version 提供 Daedalus Go 核心模块的版本与模块路径常量。
//
// 后续任务(审计库 / MCP 能力服务器 / 插件层)统一引用本包,
// 避免版本字符串与导入路径散落在各处造成漂移。
package version

// Version 是当前 Daedalus Go 核心的发布版本号(语义化版本)。
// 随后续任务的功能落地由发布流程统一递增。
const Version = "0.1.0"

// ModulePath 是本仓库 Go 工作区的模块导入路径,
// 同时也是所有内部包(internal/...)导入路径的固定前缀。
const ModulePath = "github.com/Daedalusys/daedalus-core"
