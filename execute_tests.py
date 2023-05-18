import subprocess


def run_rust_tests():
    directories = ["RC", "RRC", "mset-mu-hash", "unf-arc-based-on-rc", "unf-arc-based-on-rrc", "s-rid-rc"]
    for directory in directories:
        try:
            result = subprocess.run("cd " + directory + "/src/ ;cargo test;cd ../..", shell=True, text=True)

            if result.returncode == 0:
                print(f"Directory {directory} tests passed successfully.")
            else:
                print("Rust tests failed.")
        except subprocess.CalledProcessError:
            print("Error running Rust tests.")


if __name__ == "__main__":
    run_rust_tests()