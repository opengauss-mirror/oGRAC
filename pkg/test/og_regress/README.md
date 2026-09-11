## 解决的问题

1、openGauss_ograc通过门禁一键编译部署运行样例能够保证提交合入代码不会影响基础功能
2、开发者能够通过执行mtr保证代码质量

## 使用方法

`local_install.sh compile` 不会生成 `og_regress`。在 `build` 目录执行（若当前在仓库根目录，先 `cd build`）：

```shell
source ./common.sh
strip -N main "${OGRACDB_OUTPUT}/lib/libogserver.a"
cd pkg/test/og_regress
make -sj 8
cd "${CODE_HOME_PATH}"
```

编好 `og_regress` 后，在仓库根目录运行回归测试（**不要**再带 `need_compile`）：

```shell
bash pkg/test/og_regress/do_all_test.sh
```

从未编译过时才加 `need_compile`（会触发完整编译）：

```shell
bash pkg/test/og_regress/do_all_test.sh need_compile
```

输出：

```
Test Result: ERROR     # 样例执行失败，控制台上方可以看到哪些样例失败
Test Result: Success   # 样例执行成功
```

## 增减样例

开发者通过往 `pkg/test/og_regress/og_schedule_part1` 中增减样例，例如：

```
test: og_union_all og_union og_datatype   # 多个样例并行执行
test: og_having                          # 单次执行单个用例
```

## 结果

样例执行结果保存在 `pkg/test/og_regress/results` 中，预期结果存在 `pkg/test/og_regress/expected`。
