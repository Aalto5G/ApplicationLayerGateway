import os
import pwd
import grp


#path to create the ALG service
file_Path = '/lib/systemd/system'
file_name = 'alg.service'
FILENAME= file_Path + '/' + file_name


#path to copy the template
Working_Dir = os.path.dirname(os.path.abspath(__file__))
working_file= os.path.join(Working_Dir, '../src/{}'.format(file_name))
working_file = os.path.abspath(os.path.realpath(working_file))


uid= os.getuid()
if "SUDO_UID" in os.environ:
   uid = int(os.environ["SUDO_UID"])
   current_user= pwd.getpwuid(uid).pw_name

gid = pwd.getpwuid(uid)[3]
group = grp.getgrgid(gid)[0]


alg_file = 'alg.py'

path_to_alg= os.path.abspath(os.path.realpath(alg_file))

with open(working_file) as f:
    with open(FILENAME,'a') as f1:

        for lines in f.readlines():

            if lines.startswith('ExecStart'):
                print(lines)
                replacement='ExecStart=/usr/bin/python3 {} -user "{}" -group "{}"'.format(path_to_alg,current_user,group)
                lines=replacement

            f1.writelines(lines)
f.close()
f1.close()


myCmd = 'systemctl daemon-reload'
os.system(myCmd)

myCmd2 = 'systemctl enable alg.service'
os.system(myCmd2)

myCmd3 = 'systemctl start alg.service'
os.system(myCmd3)
