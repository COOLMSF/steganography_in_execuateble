import sys
import r2pipe

def extract_ehframe(infile, outfile):
    # store needed (eh_frame) sessions
    ehframe_sessions = []

    r2 = r2pipe.open(infile)
    r2.cmd("aaa")
    allsessions = r2.cmd("iS").split('\n')

    for allsession in allsessions:
        if "eh_frame" in allsession:
            ehframe_sessions.append(allsession)

    # ehframe_sessions will contains .eh_frame_hdr and .eh_frame
    # we only need .eh_frame
    data_size = 0x4
    print(ehframe_sessions)
    ehframe_session = ehframe_sessions[-1]
    ehframe_session_start_addr = ehframe_session.split(' ')[6]
    ehframe_session_size = ehframe_session.split(' ')[5]
    data_start_addr = hex(int(ehframe_session_start_addr, 16) + int(ehframe_session_size, 16) - data_size - 0x5)

    # print(ehframe_session_start_addr)
    # print(type(ehframe_session_start_addr))

    print("ehframe_session_start_addr:" + hex(int(ehframe_session_start_addr, 16)))
    print("ehframe_session_size:" + hex(int((ehframe_session_size), 16)))

    print("[+] Seeking to start address")
    # seek to start address
    r2.cmd("s " + hex(int(data_start_addr, 16)))
    # wtf
    print("[+] Write result to file")
    r2.cmd("wtf " + outfile +  " " + str(data_size))

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("usage: " + sys.argv[0] + "infile " + "outfile")
        exit()
    print(sys.argv[1] + sys.argv[2])
    extract_ehframe(sys.argv[1], sys.argv[2])
