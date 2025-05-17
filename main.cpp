#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <map>
#include <chrono>

class Baju {
public:
    int id;
    int harga;
    float ulasan;

    Baju() : id(0), harga(0), ulasan(0.0f) {}
    Baju(int id, int harga, float ulasan) : id(id), harga(harga), ulasan(ulasan) {}
};

class PemilihanBaju {
private:
    std::map<int, Baju> daftarBaju;

public:
    void bacaCSV(const std::string& namaFile) {
        std::ifstream file(namaFile);
        if (!file.is_open()) {
            std::cerr << "Gagal membuka file: " << namaFile << std::endl;
            return;
        }

        std::string baris;
        std::getline(file, baris); // Skip header

        while (std::getline(file, baris)) {
            std::stringstream ss(baris);
            std::string idStr, nama, hargaStr, ulasanStr;

            std::getline(ss, idStr, ',');
            std::getline(ss, nama, ','); // Nama tidak digunakan
            std::getline(ss, hargaStr, ',');
            std::getline(ss, ulasanStr, ',');

            if (idStr.empty() || hargaStr.empty() || ulasanStr.empty()) {
                std::cerr << "[Warning] Data tidak lengkap: " << baris << "\n";
                continue;
            }

            try {
                int id = std::stoi(idStr);
                int harga = std::stoi(hargaStr);
                float ulasan = std::stof(ulasanStr);
                daftarBaju[id] = Baju(id, harga, ulasan);
            } catch (const std::exception& e) {
                std::cerr << "Gagal parsing: " << baris << " (" << e.what() << ")\n";
                continue;
            }
        }

        file.close();
    }

    Baju cariDenganRatingTertinggi() {
        Baju terbaik;
        float maxRating = -1.0f;

        for (const auto& [id, baju] : daftarBaju) {
            if (baju.ulasan > maxRating) {
                maxRating = baju.ulasan;
                terbaik = baju;
            }
        }

        return terbaik;
    }
};

int main() {
    std::string namaFile = "baju.csv";  // Ganti sesuai nama file kamu
    auto mulai = std::chrono::high_resolution_clock::now();

    PemilihanBaju pemilih;
    pemilih.bacaCSV(namaFile);
    Baju terbaik = pemilih.cariDenganRatingTertinggi();

    auto selesai = std::chrono::high_resolution_clock::now();
    auto durasi = std::chrono::duration_cast<std::chrono::nanoseconds>(selesai - mulai).count();

    // Output hasil
    if (terbaik.ulasan > 0) {
        std::cout << "== Baju dengan Rating Tertinggi ==\n";
        std::cout << "ID     : " << terbaik.id << "\n";
        std::cout << "Harga  : " << terbaik.harga << "\n";
        std::cout << "Rating : " << terbaik.ulasan << "\n";
    } else {
        std::cout << "Tidak ada data valid.\n";
    }

    std::cout << "Waktu komputasi: " << durasi << " nanodetik" << std::endl;
if (terbaik.ulasan > 0) {
    std::cout << "== Baju dengan Rating Tertinggi ==\n";
    std::cout << "ID     : " << terbaik.id << "\n";
    std::cout << "Harga  : " << terbaik.harga << "\n";
    std::cout << "Rating : " << terbaik.ulasan << "\n";
} else {
    std::cout << "Tidak ada data valid.\n";
}

// CETAK WAKTU DI LUAR IF agar SELALU tampil
std::cout << "Waktu komputasi: " << durasi << " nanodetik\n";

    return 0;
}
