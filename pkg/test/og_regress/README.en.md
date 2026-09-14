## Problems Solved

1. openGauss_ograc ensures that the code submitted through the one-click compilation, deployment, and running example of the gatekeeper will not affect the basic functions.
2. Developers can ensure code quality by executing mtr.

## Usage

`local_install.sh compile` does not produce `og_regress`. Run the following in the `build` directory (from the repository root, `cd build` first):

```shell
source ./common.sh
strip -N main "${OGRACDB_OUTPUT}/lib/libogserver.a"
cd pkg/test/og_regress
make -sj 8
cd "${CODE_HOME_PATH}"
```

Then run the full regression from the repository root **without** `need_compile`:

```shell
bash pkg/test/og_regress/do_all_test.sh
```

Use `need_compile` only when the tree has never been compiled (it triggers a full rebuild):

```shell
bash pkg/test/og_regress/do_all_test.sh need_compile
```

Output:

```
Test Result: ERROR     # some cases failed; see the console above for names
Test Result: Success   # all cases passed
```

## Adding or Removing Test Cases

Developers can add or remove test cases in `pkg/test/og_regress/og_schedule_part1`. For example:

```
test: og_union_all og_union og_datatype   # run multiple cases in parallel
test: og_having                          # run a single case
```

## Results

The test results are saved in `pkg/test/og_regress/results`. Expected results are in `pkg/test/og_regress/expected`.
