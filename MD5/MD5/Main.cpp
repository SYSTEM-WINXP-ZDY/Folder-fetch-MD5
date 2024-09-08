#include <iostream>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <cstring>
#include <vector>
#include <cstdint>
#include <filesystem>
#include <io.h>
#include <iostream>
using namespace std;

// MD5算法实现
class MD5 {
public:
    MD5() { init(); }
    void update(const uint8_t* input, size_t length);
    std::string finalize();

private:
    void init();
    void transform(const uint8_t* block);
    void encode(uint8_t* output, const uint32_t* input, size_t length);
    void decode(uint32_t* output, const uint8_t* input, size_t length);

    uint32_t state[4];
    uint32_t count[2];
    uint8_t buffer[64];
};

void MD5::init() {
    count[0] = count[1] = 0;
    state[0] = 0x67452301;
    state[1] = 0xEFCDAB89;
    state[2] = 0x98BADCFE;
    state[3] = 0x10325476;
    memset(buffer, 0, sizeof(buffer));
}

void MD5::update(const uint8_t* input, size_t length) {
    size_t index = (count[0] >> 3) & 0x3F;
    size_t partLength = 64 - index;

    count[0] += length << 3;
    if (count[0] < (length << 3)) {
        count[1]++;
    }
    count[1] += length >> 29;

    size_t i = 0;
    if (length >= partLength) {
        memcpy(&buffer[index], input, partLength);
        transform(buffer);
        for (i = partLength; i + 63 < length; i += 64) {
            transform(&input[i]);
        }
        index = 0;
    }

    memcpy(&buffer[index], &input[i], length - i);
}

std::string MD5::finalize() {
    static const uint8_t padding[64] = { 0x80 };
    uint8_t bits[8];
    encode(bits, count, 8);
    size_t index = (count[0] >> 3) & 0x3F;
    size_t padLength = (index < 56) ? (56 - index) : (120 - index);
    update(padding, padLength);
    update(bits, 8);

    uint8_t digest[16];
    encode(digest, state, 16);

    std::ostringstream result;
    for (size_t i = 0; i < 16; i++) {
        result << std::hex << std::setw(2) << std::setfill('0') << (int)digest[i];
    }
    return result.str();
}

void MD5::encode(uint8_t* output, const uint32_t* input, size_t length) {
    for (size_t i = 0; i < length / 4; i++) {
        output[i * 4] = (input[i]) & 0xFF;
        output[i * 4 + 1] = (input[i] >> 8) & 0xFF;
        output[i * 4 + 2] = (input[i] >> 16) & 0xFF;
        output[i * 4 + 3] = (input[i] >> 24) & 0xFF;
    }
}

void MD5::decode(uint32_t* output, const uint8_t* input, size_t length) {
    for (size_t i = 0; i < length / 4; i++) {
        output[i] = (input[i * 4]) |
            (input[i * 4 + 1] << 8) |
            (input[i * 4 + 2] << 16) |
            (input[i * 4 + 3] << 24);
    }
}

// MD5变换函数
void MD5::transform(const uint8_t* block) {
    static const uint32_t S[64] = {
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
    };
    static const uint32_t K[64] = {
        0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE, 0xF57C0FAF, 0x4787C62A, 0xA8304613, 0xFD469501,
        0x698098D8, 0x8B44F7AF, 0xFFFF5BB1, 0x895CD7BE, 0x6B901122, 0xFD987193, 0xA679438E, 0x49B40821,
        0xF61E2562, 0xC040B340, 0x265E5A51, 0xE9B6C7AA, 0xD62F105D, 0x02441453, 0xD8A1E681, 0xE7D3FBC8,
        0x21E1CDE6, 0xC33707D6, 0xF4D50D87, 0x455A14ED, 0xA9E3E905, 0xFCEFA3F8, 0x676F02D9, 0x8D2A4C8A,
        0xFFFA3942, 0x8771F681, 0x6D9D6122, 0xFDE5380C, 0xA4BEEA44, 0x4BDECFA9, 0xF6BB4B60, 0xBEBFBC70,
        0x289B7EC6, 0xEAA127FA, 0xD4EF3085, 0x04881D05, 0xD9D4D039, 0xE6DB99E5, 0x1FA27CF8, 0xC4AC5665,
        0xF4292244, 0x432AFF97, 0xAB9423A7, 0xFC93A039, 0x655B59C3, 0x8F0CCC92, 0xFFEFF47D, 0x85845DD1,
        0x6FA87E4F, 0xFE2CE6E0, 0xA3014314, 0x3B53A99B, 0x9A65B3D1, 0xE0D74C83, 0xF4A7B43E, 0x6F635D8B
    };

    uint32_t a = state[0];
    uint32_t b = state[1];
    uint32_t c = state[2];
    uint32_t d = state[3];

    uint32_t x[16];
    decode(x, block, 64);

    for (size_t i = 0; i < 64; i++) {
        uint32_t f, g;
        if (i < 16) {
            f = (b & c) | (~b & d);
            g = i;
        }
        else if (i < 32) {
            f = (d & b) | (~d & c);
            g = (5 * i + 1) % 16;
        }
        else if (i < 48) {
            f = b ^ c ^ d;
            g = (3 * i + 5) % 16;
        }
        else {
            f = c ^ (b | ~d);
            g = (7 * i) % 16;
        }
        f += a + K[i] + x[g];
        a = d;
        d = c;
        c = b;
        b += ((f << S[i]) | (f >> (32 - S[i])));
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
}

std::string compute_md5(const std::string& file_path) {
    std::ifstream file(file_path, std::ios::binary);
    if (!file.is_open()) {
        return "Error: Unable to open file.";
    }

    MD5 md5;
    std::vector<uint8_t> buffer(1024);
    while (file.read(reinterpret_cast<char*>(buffer.data()), buffer.size())) {
        md5.update(buffer.data(), file.gcount());
    }
    md5.update(buffer.data(), file.gcount());

    return md5.finalize();
}

void DfsListFolderFiles(const string& path, ofstream& output_file) {
    _finddata_t file_info;
    string search_path = path + "\\*.*";
    intptr_t handle = _findfirst(search_path.c_str(), &file_info);

    if (handle == -1) {
        return;
    }

    do {
        if ((file_info.attrib & _A_SUBDIR) != 0) {
            if (strcmp(file_info.name, ".") != 0 && strcmp(file_info.name, "..") != 0) {
                string new_path = path + "\\" + file_info.name;
                DfsListFolderFiles(new_path, output_file);
            }
        }
        else {
            string file_path = path + "\\" + file_info.name;
            string md5 = compute_md5(file_path);
            output_file << md5 << endl; // 只写入 MD5 值
        }
    } while (_findnext(handle, &file_info) == 0);

    _findclose(handle);
}

int main() {
    string folder_path = "C:\\Windows\\System32";
    ofstream output_file("md5_output.txt");

    if (output_file.is_open()) {
        DfsListFolderFiles(folder_path, output_file);
        output_file.close();
    }
    else {
        cerr << "错误: 无法打开输出文件。" << endl;
    }

    return 0;
}