=================================
关于 uniref
=================================

uniref 是一个辅助分析 Unity 应用的框架。它可以帮助您获取 Unity 应用中的类、方法、成员变量等的反射信息，让您实时地查看和操作它们。
您可以将您的一些分析结果借助本框架转化为少量的 Python 代码，在一定程度上方便您进行 Unity 应用的插件开发。


适用场景
-----------------

uniref 同时支持 Mono 和 IL2CPP 两种脚本后端（Unity scripting backend）。

在 Windows x86 64 位平台下，大部分基于 C# 开发的 Unity 应用都可以使用 uniref 来获取反射信息。


实现方式
-----------------

在指定一个进程来实例化 WinUniRef 类时，uniref 会尝试从目标进程的所有已加载模块中找到 Mono / IL2CPP 相关模块，
并从中收集一些用于获取关键信息的导出函数。

在找到这些函数后，uniref 会创建远程线程并按照一定的组合顺序在目标进程中调用它们。之后便是收集并处理返回值，以用户友好的形式将反射信息呈现给开发者。

由于远程线程的某些特性，uniref 提供的一些 API 调用可能会失败。最坏的情况下，可能会导致应用 crash。
如果您遇到这种情况，烦请在 `Issues <https://github.com/in1nit1t/uniref/issues>`_ 页面提交报告，并描述机器环境与错误复现步骤，这边将尽力提升框架的兼容性与稳定性。


下一步计划
-----------------

- 支持分析 Android 平台 Unity 应用
- 鉴于 Windows 平台上远程线程的不稳定因素，考虑更换另一种进程注入方式


参与进来
-----------------

如果您有合理的建议或者需求，同样欢迎您提 `issue <https://github.com/in1nit1t/uniref/issues>`_

当然，如果您有兴趣一起建设这个框架，欢迎提交 `Pull requests <https://github.com/in1nit1t/uniref/pulls>`_


开源协议
-----------------

`GNU Affero General Public License v3.0 <https://github.com/in1nit1t/uniref/blob/main/LICENSE>`_