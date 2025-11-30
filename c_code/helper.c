#include <math.h>

// deadass asked AI to make these for me.
// lol

float mean(float arr[], int n) {
    float sum = 0;
    for (int i = 0; i < n; i++) {
        sum += arr[i];
    }
    return sum / n;
}

float std(float arr[], int n) {
    float m = mean(arr, n);
    float sum_sq_diff = 0;
    for (int i = 0; i < n; i++) {
        sum_sq_diff += (arr[i] - m) * (arr[i] - m);
    }
    return sqrt(sum_sq_diff / n);
}

float max(float arr[], int n) {
    float max_val = arr[0];
    for (int i = 1; i < n; i++) {
        if (arr[i] > max_val) {
            max_val = arr[i];
        }
    }
    return max_val;
}

float min(float arr[], int n) {
    float min_val = arr[0];
    for (int i = 1; i < n; i++) {
        if (arr[i] < min_val) {
            min_val = arr[i];
        }
    }
    return min_val;
}
