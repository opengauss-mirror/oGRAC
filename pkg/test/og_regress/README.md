## 解决的问题
1、openGauss_ograc通过门禁一键编译部署运行样例能够保证提交合入代码不会影响基础功能
2、开发者能够通过执行mtr保证代码质量

## 使用方法
运行``测试``脚本

```bash
bash xxx/pkg/test/og_regress/do_all_test.sh need_compile
```
注 need_compile：执行编译，当已经编译过可不加此参数
输出：
Test Result: ERROR    --样例执行失败，出现执行失败，在控制台上方可以看到哪些样例失败
Test Result: SUCCESS  --样例执行成功
    

## 增减样例
开发者通过往"xxx/pkg/test/og_regress/og_schedule_part1"中增减样例，例如：
test: og_union_all og_union og_datatype （多个样例并行执行）
test: og_having  (单次执行单个用例)

## 结果
样例执行结果保存在"xxx/pkg/test/og_regress/results"中，预期结果存在"xxx/pkg/test/og_regress/expected"
