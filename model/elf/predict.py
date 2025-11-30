import xgboost as xgb
import sys
import json
import lief
import numpy as np
from scipy.stats import entropy as scipy_entropy
import time
import threading
from colorama import Fore, Style
import typer
from enum import Enum
import re
import os

app = typer.Typer()

class Colorblindness(str, Enum):
    protanopia = "protanopia"

def calculate_entropy(data):
  counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
  probs = counts / len(data)
  probs = probs[probs > 0]
  return scipy_entropy(probs, base=2)

def calculate_byte_entropy(data, block_size=1024):
  entropies = []
  for i in range(0, len(data), block_size):
    block = data[i:i+block_size]
    if not block:
      continue
    entropy = calculate_entropy(block)
    entropies.append(entropy)
  return np.array(entropies)

def extract_strings(data: bytes, min_len=4):
  # find sequences of printable ASCII chars of at least min_len
  pattern = rb'[ -~]{' + str(min_len).encode() + rb',}'
  return [s.decode(errors="ignore") for s in re.findall(pattern, data)]

def extract_features_from_file_elf(filepath: str):
  binary = lief.parse(filepath)
  with open(filepath, "rb") as f:
    data = f.read()
  strings = extract_strings(data)
  hist, _ = np.histogram(np.frombuffer(data, dtype=np.uint8), bins=256, range=(0,256))
  entropy = calculate_entropy(data)

  # i assume avlength is average length
  if strings:
    avlength = sum(len(s) for s in strings) / len(strings)
  else:
    avlength = 0

  return [
      len(data),
      np.mean(hist),
      np.std(hist),
      np.max(hist),
      np.min(hist),
      entropy,
      len(strings),
      avlength,
      np.mean(entropy),
      np.max(entropy)
  ]
  """
  sample["general"]["size"],
  np.mean(hist),
  np.std(hist),
  np.max(hist),
  np.min(hist),
  sample["strings"]["entropy"],
  sample["strings"]["numstrings"],
  sample["strings"]["avlength"],

  # byte entropy, this indicates compression/encryption
  np.mean(sample["byteentropy"]),
  np.max(sample["byteentropy"])
  """

def checking_placeholder(filepath, done_predicting):
    while not done_predicting:
        for i in range(1,4):
            print(f"\rChecking if {filepath} is a malware{'.'*i}", end="", flush=True)
            time.sleep(0.2)


script_dir = os.path.dirname(os.path.abspath(__file__))
default_model_dir = os.path.join(script_dir, "model.json")
@app.command()
def predict_malware(filepath: str = typer.Option(), model_path: str = typer.Option(default_model_dir), colorblindness: Colorblindness = typer.Option(None)):
    done_predicting = False
    thread = threading.Thread(target=checking_placeholder, args=(filepath, done_predicting), daemon=True)
    thread.start()

    model = xgb.XGBClassifier()
    model.load_model(model_path)

    features = extract_features_from_file_elf(filepath)
    features = np.array(features).reshape(1, -1)
    pred = model.predict(features)

    # done_predicting = True
    print()
    is_malware = True if pred[0] else False
    red = Fore.YELLOW if colorblindness == Colorblindness.protanopia else Fore.RED
    print(Style.BRIGHT + red + "[POSSIBLE THREAT]" if is_malware else Style.BRIGHT + Fore.GREEN + "[SAFE]", end=" ")
    print(Style.RESET_ALL + Fore.RESET, end="")
    print("It's a malware" if is_malware else "It's not a malware")

if __name__ == "__main__":
    app()

