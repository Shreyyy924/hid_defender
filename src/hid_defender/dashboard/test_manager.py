import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Dict

class TestManager:
    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.test_dir = project_root / "tests"

    def discover_tests(self) -> List[Dict]:
        """Discover test functions from Chapter-4 test files."""
        priority_files = ["test_unit_cases.py", "test_system_cases.py"]
        all_files = (
            [self.test_dir / f for f in priority_files if (self.test_dir / f).exists()]
            + sorted(f for f in self.test_dir.glob("test_*.py")
                     if f.name not in priority_files)
        )

        tests = []
        for test_file in all_files:
            module_name = test_file.stem
            try:
                content = test_file.read_text(encoding="utf-8")
                # Find class names and their docstrings for friendly labels
                class_docs = {}
                for m in re.finditer(r'class\s+(Test\w+)[^:]*:\s*\n\s+"""([^"]+)"""', content):
                    class_docs[m.group(1)] = m.group(2).strip()

                # Find every test_ method
                for m in re.finditer(r'def\s+(test_\w+)\s*\(', content):
                    func = m.group(1)
                    # Guess which class owns this function
                    class_name = ""
                    for cm in re.finditer(r'class\s+(Test\w+)', content[:content.index(func)]):
                        class_name = cm.group(1)

                    label = class_docs.get(class_name, class_name) or func
                    tests.append({
                        "id":     f"{module_name}::{class_name}::{func}" if class_name else f"{module_name}::{func}",
                        "module": module_name,
                        "class":  class_name,
                        "name":   func,
                        "label":  label,
                        "file":   test_file.name,
                    })
            except Exception as e:
                print(f"Error reading {test_file}: {e}")
        return tests

    def run_test(self, test_id: str) -> Dict:
        """Run a specific pytest test_id and return pass/fail + output."""
        parts = test_id.split("::")
        module_name = parts[0]
        test_path   = str(self.test_dir / f"{module_name}.py")

        venv_pytest = self.project_root / ".venv" / "Scripts" / "pytest.exe"
        if not venv_pytest.exists():
            venv_pytest = self.project_root / ".venv" / "bin" / "pytest"
        pytest_cmd = [str(venv_pytest)] if venv_pytest.exists() else [sys.executable, "-m", "pytest"]

        try:
            result = subprocess.run(
                pytest_cmd + [test_path, "::" .join(parts[1:]) and f"{test_path}::{parts[1]}" or test_path,
                              "-v", "--tb=short", "--no-header", "-q"],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=60,
            )
            return {
                "passed":     result.returncode == 0,
                "stdout":     result.stdout,
                "stderr":     result.stderr,
                "returncode": result.returncode,
            }
        except subprocess.TimeoutExpired:
            return {"passed": False, "stdout": "", "stderr": "Timed out", "returncode": -1}
        except Exception as e:
            return {"passed": False, "stdout": "", "stderr": str(e), "returncode": -1}

    def run_all_tests(self, pattern: str = "") -> Dict:
        """Run the full test suite and return summary."""
        venv_pytest = self.project_root / ".venv" / "Scripts" / "pytest.exe"
        if not venv_pytest.exists():
            venv_pytest = self.project_root / ".venv" / "bin" / "pytest"
        pytest_cmd = [str(venv_pytest)] if venv_pytest.exists() else [sys.executable, "-m", "pytest"]

        target = str(self.test_dir / f"{pattern}.py") if pattern else str(self.test_dir)
        try:
            result = subprocess.run(
                pytest_cmd + [target, "-v", "--tb=short", "--no-header"],
                cwd=self.project_root,
                capture_output=True, text=True, timeout=120,
            )
            summary = result.stdout.split("\n")[-3] if result.stdout else ""
            passed  = len(re.findall(r" PASSED", result.stdout))
            failed  = len(re.findall(r" FAILED", result.stdout))
            errors  = len(re.findall(r" ERROR",  result.stdout))

            return {
                "passed":     result.returncode == 0,
                "pass_count": passed,
                "fail_count": failed,
                "error_count":errors,
                "summary":    summary,
                "stdout":     result.stdout[-8000:],   # trim for JSON size
                "stderr":     result.stderr[-2000:],
                "timestamp":  datetime.now().isoformat(),
            }
        except subprocess.TimeoutExpired:
            raise TimeoutError("Test suite timed out")
        except Exception as e:
            raise e
