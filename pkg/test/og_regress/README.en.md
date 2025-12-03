## Problems Solved
1. openGauss_ograc ensures that the code submitted through the one-click compilation, deployment, and running example of the gatekeeper will not affect the basic functions.
2. Developers can ensure code quality by executing mtr.
## Usage
Run the test script:
```bash
bash xxx/pkg/test/og_regress/do_all_test.sh need_compile
```
Note: need_compile is used to trigger the compilation process. If the code has already been compiled, this parameter can be omitted.
Output:
Test Result: ERROR    -- Test case execution failed. You can see which test cases failed at the top of the console.
Test Result: SUCCESS  -- Test case execution succeeded.
## Adding or Removing Test Cases
Developers can add or remove test cases in the directory "xxx/pkg/test/og_regress/og_schedule_part1". For example:
To run multiple test cases in parallel: test: og_union_all og_union og_datatype
To run a single test case: test: og_having
## Results
The test results are saved in the directory "xxx/pkg/test/og_regress/results", while the expected results are stored in the directory "xxx/pkg/test/og_regress/expected".
