import idc
import re

path=""#填入dump.cs的路径,反斜杠记得转义
file=open(path,'r')
file_contents=file.readlines()

def rename_function(ea, new_name):
    func_name = idc.get_func_name(ea)
    if func_name:
        idc.set_name(ea, new_name)
        print("函数:0x%x重命名为%s" % (ea, new_name))
        return 0
    else:
        #print("地址0x%x不是有效的函数地址" % ea)
        idc.del_items(ea,0,1)
        if  idc.set_name(ea, new_name):
            print("混淆的函数:0x%x重命名为%s" % (ea, new_name))
            return 0
        else:
            print("命名失败", hex(ea))
            return 1
classname=''
errortimes=0
for index,value in enumerate(file_contents):
    if ('{' in value)==1 and ('}' in value)==0:
        match = re.search( r'(?<=class )\b[0-9a-zA-Z]+\b', file_contents[index-1], re.M|re.I)
        if match:
            classname=match.group()
    if  'RVA' in value:
        matchRVA = re.search( r'(?<=RVA: )\b0x[0-9a-fA-F]+\b',value, re.M|re.I)
        if matchRVA:
            RVA=int(matchRVA.group(),16)
            match=re.search( r'\b[0-9a-zA-Z_]+\b(?=[(])', file_contents[index+1], re.M|re.I)
            if match:
                tmpname=match.group()
                func_name=classname+'.'+tmpname+'_'+matchRVA.group()
                errortimes+=rename_function(RVA,func_name)
print('命名失败的个数:',errortimes)
