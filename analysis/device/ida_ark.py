# IDAPython: «развернуть» все защищённые переходы libng.so (.ark)
#
# Запуск: File -> Script file... -> ida_ark.py
# Требуется analysis/out/ark_sites.csv (колонки: site_va,record_va,record_index,target_va,len,extra_len,checksum)
# Что делает: для каждого сайта ставит комментарий и создаёт код-ссылку на реальную цель,
# т.е. снимает obfuscation indbr/icall (после этого декомпилятор видит настоящие вызовы).

import csv, os
import idaapi, idc, ida_bytes, ida_xref, ida_funcs, ida_nalt

CSV_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'out', 'ark_sites.csv')

def main():
    if not os.path.exists(CSV_PATH):
        print('нет файла', CSV_PATH); return
    n = 0
    with open(CSV_PATH) as f:
        for row in csv.DictReader(f):
            site = int(row['site_va'], 16)
            tgt = int(row['target_va'], 16)
            idx = row['record_index']
            try:
                idc.set_cmt(site, 'ark#%s -> 0x%x (len=%s)' % (idx, tgt, row['len']), 0)
                ida_xref.add_cref(site, tgt, ida_xref.fl_CN)
                # сделать цель именованной функцией, если это код
                if ida_funcs.get_func(tgt) is None:
                    ida_funcs.add_func(tgt)
                n += 1
            except Exception as e:
                pass
    print('обработано сайтов: %d' % n)
    idaapi.info('libng.so: развёрнуто %d защищённых переходов (.ark)' % n)

if __name__ == '__main__':
    main()
