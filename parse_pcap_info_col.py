import pandas as pd
import re

# FUNCTIONS

def parse_info(info):
    result = {
        'src_port': None,
        'dst_port': None,
        'flag_syn': 0,
        'flag_ack': 0,
        'flag_psh': 0,
        'flag_fin': 0,
        'flag_rst': 0,
        'seq': None,
        'ack_num': None,
        'win': None,
        'payload_len': None,
        'tcp_anomaly': None,
        'size_limited': 0,
    }

    # find TCP anomaly such as: TCP Out-Of-Order
    anomaly = re.search(r'\[(TCP [^\]]+)\]', info)
    if anomaly:
        result['tcp_anomaly'] = anomaly.group(1)

    # extract ports
    clean = re.sub(r'\[[^\]]*\]', '', info).strip()
    ports = re.match(r'(\d+)\s+>\s+(\d+)', clean)
    if ports:
        result['src_port'] = int(ports.group(1))
        result['dst_port'] = int(ports.group(2))

    # extract TCP flags
    flags = re.search(r'\[([A-Z, ]+)\]', info)
    if flags:
        flag_str = flags.group(1)
        result['flag_syn'] = int('SYN' in flag_str)
        result['flag_ack'] = int('ACK' in flag_str)
        result['flag_psh'] = int('PSH' in flag_str)
        result['flag_fin'] = int('FIN' in flag_str)
        result['flag_rst'] = int('RST' in flag_str)

    # extract Seq, Ack, Win, Len values
    for field, key in [('Seq', 'seq'), ('Ack', 'ack_num'), ('Win', 'win'), ('Len', 'payload_len')]:
        match = re.search(rf'{field}=(\d+)', info)
        if match:
            result[key] = int(match.group(1))

    # flag truncated packets
    result['size_limited'] = int('size limited' in info.lower())

    return result

def parse_and_save(input_path, output_path):
    df = pd.read_csv(input_path)
    parsed = df['Info'].apply(parse_info).apply(pd.Series)
    df_out = pd.concat([df, parsed], axis=1)
    df_out.to_csv(output_path, index=False)
    print(f'Done! Saved to {output_path} — {len(df_out)} rows, {len(df_out.columns)} columns')
    return df_out


if __name__ == '__main__':
    input_file = 'test_pcap.csv'   # input file
    output_file = f'parsed_{input_file}'  # output file

    parse_and_save(input_file, output_file)
