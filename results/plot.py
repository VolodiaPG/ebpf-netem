import seaborn as sns
import pandas as pd
from typing import List
from matplotlib import pyplot as plt
from matplotlib import ticker as tick
from plot_utils import plot_set_font, plot_set_size


PAPER_WIDTH = 516.0


def main():
    # read files
    lat_htb_df = pd.read_csv("latency_htb.csv", index_col="Filters")
    bandwidth_htb_df = pd.read_csv("bandwidth_htb.csv", index_col="Filters")
    lat_htb_match_df = pd.read_csv("latency_htb_match_1000.csv", index_col="Filters")
    bandwidth_htb_match_df = pd.read_csv(
        "bandwidth_htb_match_1000.csv", index_col="Filters"
    )
    lat_ebpf_df = pd.read_csv("latency_ebpf.csv", index_col="Filters")
    bandwidth_ebpf_df = pd.read_csv("bandwidth_ebpf.csv", index_col="Filters")
    setup_exp_df = pd.read_csv("log-1024.csv")
    setup_gcp = pd.read_csv("log-1024-gcp.csv")
    setup_metal = pd.read_csv("ec2-metal.csv")

    # plot_setup_exp(setup_exp_df)
    # plot_setup_exp_ecdf(setup_exp_df)
    # plot_setup_time_per_link(setup_exp_df, filename="time_per_link_rel_bare.pdf")
    # plot_setup_time_per_link(setup_gcp, filename="time_per_link_rel_gcp.pdf")
    plot_setup_time_per_link(setup_metal, filename="time_per_link_rel_metal.pdf")

    # plot single graphs
    plot_latency(
        lat_htb_df,
        title="HTB: latency by filter (no match)",
        filename="latency_htb.pdf",
    )
    plot_bandwidth(
        bandwidth_htb_df,
        title="HTB: bandwidth by filter (no match)",
        filename="bandwidth_htb.pdf",
    )
    plot_latency(
        lat_ebpf_df,
        title="eBPF: latency by filter (no match)",
        filename="latency_ebpf.pdf",
    )
    plot_bandwidth(
        bandwidth_ebpf_df,
        title="eBPF: bandwidth by filter (no match)",
        filename="bandwidth_ebpf.pdf",
    )

    ## plot combined graphs
    plot_latency_combined(
        lat_htb_df,
        lat_ebpf_df,
        title="HTB vs eBPF: latency by filter (no match)",
        filename="latency_combined.pdf",
    )
    plot_bandwidth_combined(
        bandwidth_htb_df,
        bandwidth_ebpf_df,
        title="HTB vs eBPF: bandwidth by filter (no match)",
        filename="bandwidth_combined.pdf",
    )

    plot_latency_htb_matched(
        lat_htb_df, lat_htb_match_df, filename="latency_htb_match-1000.pdf"
    )
    plot_bandwidth_htb_matched(
        bandwidth_htb_df,
        bandwidth_htb_match_df,
        filename="bandwidth_htb_match-1000.pdf",
    )


def plot_latency_htb_matched(
    df_nomatch: pd.DataFrame, df_match: pd.DataFrame, filename: str
):
    sns.set(style="darkgrid")
    plot_set_font()
    combined = pd.concat(
        [df_nomatch, df_match], keys=["No match", "1000"], names=["Matched filter"]
    )
    fig, axs = plt.subplots(1, 1, figsize=plot_set_size(PAPER_WIDTH, fraction=0.5))
    g = sns.lineplot(
        data=combined,
        x="Filters",
        y="Avg Latency",
        style="Matched filter",
        hue="Matched filter",
        palette="muted",
        # markers=True,
        ax=axs,
    )
    g.set_xlabel("number of filters")
    g.set_ylabel("Avg latency [ms]")
    g.grid(True)
    g.set_xlim(0, 65534)
    # g.set_ylim(0, 15)
    plt.tight_layout()
    plt.savefig(filename, format="pdf", bbox_inches="tight")


def plot_bandwidth_htb_matched(
    df_nomatch: pd.DataFrame, df_match: pd.DataFrame, filename: str
):
    sns.set(style="darkgrid")
    plot_set_font()
    combined = pd.concat(
        [df_nomatch, df_match], keys=["No match", "1000"], names=["Matched filter"]
    )
    fig, axs = plt.subplots(1, 1, figsize=plot_set_size(PAPER_WIDTH, fraction=0.5))
    g = sns.lineplot(
        data=combined,
        x="Filters",
        y="Bitrate",
        style="Matched filter",
        hue="Matched filter",
        palette="muted",
        # markers=True,
        ax=axs,
    )
    g.set_xlabel("number of filter")
    g.set_ylabel("Measured bandwidth in Gbit/s]")
    g.grid(True)
    g.set_xlim(0, 65534)
    # g.set_ylim(0, 15)
    plt.tight_layout()
    plt.savefig(filename, format="pdf", bbox_inches="tight")


def plot_latency_combined(
    df_htb: pd.DataFrame, df_ebpf: pd.DataFrame, title: str, filename: str
):
    sns.set(style="darkgrid")
    plot_set_font()
    combined = pd.concat([df_htb, df_ebpf], keys=["HTB", "eBPF"], names=["Method"])
    # print(combined.head())

    fig, axs = plt.subplots(1, 1, figsize=plot_set_size(PAPER_WIDTH, fraction=1))
    g = sns.lineplot(
        data=combined,
        x="Filters",
        y="Avg Latency",
        style="Method",
        hue="Method",
        palette="muted",
        # markers=True,
        ax=axs,
    )
    g.set_title(title)
    g.set_xlabel("Number of filters / map entries")
    g.set_ylabel("Avg latency [ms]")
    g.grid(True)
    g.set_xlim(0, 65534)
    # g.set_ylim(0, 15)
    plt.tight_layout()
    plt.savefig(filename, format="pdf", bbox_inches="tight")


def plot_bandwidth_combined(
    df_htb: pd.DataFrame, df_ebpf: pd.DataFrame, title: str, filename: str
):
    sns.set(style="darkgrid")
    plot_set_font()
    combined = pd.concat([df_htb, df_ebpf], keys=["HTB", "eBPF"], names=["Method"])
    # print(combined.head())

    fig, axs = plt.subplots(1, 1, figsize=plot_set_size(PAPER_WIDTH, fraction=1))
    g = sns.lineplot(
        data=combined,
        x="Filters",
        y="Bitrate",
        style="Method",
        hue="Method",
        palette="muted",
        # markers=True,
        ax=axs,
    )
    g.set_title(title)
    g.set_xlabel("Number of filters / map entries")
    g.set_ylabel("Measured bandwidth in Gbit/s]")
    g.grid(True)
    g.set_xlim(0, 65534)
    # g.set_ylim(0, 25)
    plt.tight_layout()
    plt.savefig(filename, format="pdf", bbox_inches="tight")


def plot_latency(df: pd.DataFrame, title: str, filename: str):
    sns.set(style="darkgrid")
    plot_set_font()
    fig, axs = plt.subplots(1, 1, figsize=(14, 4))
    g = sns.lineplot(data=df, x="Filters", y="Avg Latency", palette="muted", ax=axs)
    g.set_title(title)
    g.set_xlabel("number of filters")
    g.set_ylabel("avg latency in ms")
    g.grid(True)
    g.set_xlim(1, 65534)
    # g.set_ylim(0, 20)
    plt.tight_layout()
    plt.savefig(filename, format="pdf", bbox_inches="tight")


def plot_bandwidth(df: pd.DataFrame, title: str, filename: str):
    sns.set(style="darkgrid")
    plot_set_font()
    fig, axs = plt.subplots(1, 1, figsize=(14, 4))
    g = sns.lineplot(data=df, x="Filters", y="Bitrate", palette="muted", ax=axs)
    g.set_title(title)
    g.set_xlabel("number of filters")
    g.set_ylabel("measured bandwidth in Gbit/s")
    g.grid(True)
    g.set_xlim(1, 65534)
    # g.set_ylim(0, 25)
    plt.tight_layout()
    plt.savefig(filename, format="pdf", bbox_inches="tight")


def plot_setup_exp_ecdf(df: pd.DataFrame):
    # print(df.head())
    df["time_ms"] = df["time"] / 1e6
    fig, axs = plt.subplots(1, 1, figsize=(14, 4))
    g = sns.ecdfplot(hue="N", x="time_ms", data=df, ax=axs)
    g.set_xlabel("Time per Link (ms)")
    g.set_ylabel("Empirical Cumulative Distribution")
    plt.tight_layout()
    plt.savefig("setup-exp-ecdf.pdf", format="pdf", bbox_inches="tight")


def plot_setup_exp(df: pd.DataFrame):
    df["time_ms"] = df["time"] / 1e6
    fig, axs = plt.subplots(1, 1, figsize=(14, 4))
    g = sns.lineplot(x="index", y="time_ms", hue="N", data=df, ax=axs)
    g.set_ylabel("Time per Link (ms)")
    plt.tight_layout()
    plt.savefig("setup-exp.pdf", format="pdf", bbox_inches="tight")


def plot_setup_time_per_link(df: pd.DataFrame, filename: str):
    sns.set(style="darkgrid")
    plot_set_font()
    fig, axs = plt.subplots(1, 1, figsize=plot_set_size(PAPER_WIDTH, fraction=0.5))
    df["time_ms"] = df["time"] / 1e6
    df["index_2"] = df["i"] * df["N"] + df["j"]
    df["index_rel"] = df["index_2"] / ((df["N"]) * (df["N"] - 1) + (df["N"] - 2))
    df_graph = df
    df_graph["$N$"] = df["N"].astype(str)
    df_graph = df_graph[
        (df_graph["N"] == 128)
        | (df_graph["N"] == 256)
        | (df_graph["N"] == 512)
        | (df_graph["N"] == 1024)
    ]
    df_graph["index_rel_exp"] = df_graph["index_rel"].apply(lambda x: round(x, 2))
    df_graph["index_rel_perc"] = df_graph["index_rel"] * 100
    g = sns.lineplot(
        x="index_rel_perc",
        y="time_ms",
        hue="$N$",
        data=df_graph,
        ci="sd",
        ax=axs,
        palette="muted",
    )
    g.set_ylabel("Time per Link (ms)")
    g.set_xlabel("\% Links")
    plt.tight_layout()
    plt.savefig(filename, format="pdf", bbox_inches="tight")


if __name__ == "__main__":
    main()
