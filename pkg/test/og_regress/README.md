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

开发者通过往 `pkg/test/og_regress/og_schedule_part1` 中增减样例。一行多个用例表示并行执行，单个用例独占一行：

```
test: og_union_all og_union og_datatype
test: og_having
```

注意：schedule 文件**不支持任何注释**——`#` 开头或行尾的注释都会被解析器当作用例名导致回归失败，说明文字请写在这个 README 里，不要写进 og_schedule_* 文件。

## Smoke 用例集

冒烟用例集定义在 `og_schedule_smoke`，从全量回归（og_schedule_part1/part2）中精简而来，
用于构建/部署后快速验证核心功能（类型、DDL/DML、查询、索引、约束、视图、PL/SQL、事务）。

运行方式：

```shell
bash CI/build/script/run_ograc_test.sh smoke
# 或在已部署环境上直接指定用例清单：
bash CI/script/Dev_ograc_regress.sh --og_schedule_list og_schedule_smoke
```

新增冒烟用例时，只能从 og_schedule_part1/part2 中已有用例中挑选，保证预期结果（expected）齐备。

## 结果

样例执行结果保存在 `pkg/test/og_regress/results` 中，预期结果存在 `pkg/test/og_regress/expected`。
