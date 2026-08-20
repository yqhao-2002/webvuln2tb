#!/usr/bin/env php
<?php
// webvuln2tb openemr 证据补丁 (构建期执行一次):
// openemr 镜像的插桩只记函数名不记输入 —— grader 的元字符证据检查依赖输入内容。
// 本脚本把全部 vulnfunction_* 的 file_put_contents 补成记输入格式
// (与其他 phpbench 应用一致: 去空白后附加在函数名后)。
// 注意: 必须包含 .inc 后缀 (auth.inc / user.inc 也有插桩, 2026-08-19 实测踩过)。
$it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator('/var/www/html'));
$n = 0;
foreach ($it as $f) {
    if (!in_array($f->getExtension(), ['php', 'inc'])) continue;
    $p = $f->getPathname();
    $src = @file_get_contents($p);
    if ($src === false || strpos($src, 'insertpoint.txt') === false) continue;
    $new = preg_replace(
        '/file_put_contents\("\/var\/instr\/insertpoint\.txt", "(vulnfunction_[0-9a-f]+)\\\\n", FILE_APPEND\);/',
        'file_put_contents("/var/instr/insertpoint.txt", "$1:" . preg_replace(\'/\\s+/\', \'\', $var) . "\\\\n", FILE_APPEND);',
        $src, -1, $count);
    if ($count > 0) { file_put_contents($p, $new); $n += $count; }
}
if ($n < 80) { fwrite(STDERR, "patched=$n, expected >=80 — 插桩格式可能已变, 拒绝继续\n"); exit(1); }
echo "patched_lines=$n\n";
