cd /home/regress/ogracKernel/build
sh Makefile.sh all
cp -rf /home/regress/ogracKernel/output/bin  /home/regress/ogracKernel/pkg/
cp -rf /home/regress/ogracKernel/output/lib  /home/regress/ogracKernel/pkg/
echo ${OGDB_HOME}
if [[ ! -d ${OGDB_HOME}/data ]]; then
    mkdir -p ${OGDB_HOME}/data
fi