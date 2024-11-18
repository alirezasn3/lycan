<script lang="ts">
  import { onMount } from "svelte";
  import {
    GetVersion,
    Trace,
    GetPublicIP,
    StopTrace,
    GetInterfaces,
  } from "../wailsjs/go/main/App.js";
  import { EventsOn } from "../wailsjs/runtime/runtime";
  import "./style.css";
  import { fade, fly } from "svelte/transition";
  import "@material/web/button/filled-button.js";
  import "@material/web/textfield/outlined-text-field.js";
  import "@material/web/progress/circular-progress.js";
  import "@material/web/select/outlined-select.js";
  import "@material/web/select/select-option.js";
  import type { MdOutlinedTextField } from "@material/web/textfield/outlined-text-field";
  import type { MdOutlinedSelect } from "@material/web/select/outlined-select.js";

  interface Hop {
    number: number;
    address: string;
    ipeeInfo: IPEEInfo;
    rtt: number;
    isPrivate: boolean;
    timedOut: boolean;
    tcp: { rst: boolean };
  }

  interface IPEEInfo {
    asName: string;
    country: string;
    countryCode: string;
    organizationName: string;
  }

  let ip: MdOutlinedTextField;
  let maxHops: MdOutlinedTextField;
  let timeout: MdOutlinedTextField;
  let destinationPort: MdOutlinedTextField;
  let mss: MdOutlinedTextField;
  let error: string = "";
  let loading: boolean = false;
  let hopsEelement: HTMLDivElement;
  let hops: { [number: number]: Hop } = {};
  let route = [];
  let version = "";
  let publicIP = "";
  let lastSuccessfulDestination = "";
  let bindOn: MdOutlinedSelect;
  let protocol: MdOutlinedSelect;
  let protocolValue = "ICMP";
  let interfaces: string[][] = [];
  let logs: string[] = [];
  let showLogs = false;

  const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

  async function trace() {
    try {
      error = "";
      loading = true;
      ip.value = ip.value.trim();
      route = [];
      hops = {};
      await sleep(500);
      error = await Trace(
        bindOn.value,
        ip.value,
        Number(maxHops.value),
        Number(timeout.value),
        protocol.value,
        Number(destinationPort.value),
        Number(mss.value)
      );
      lastSuccessfulDestination = error === "" ? ip.value : "";
      for (let i = 1; i <= Object.values(hops).length; i++) {
        if (
          hops[i]?.ipeeInfo?.country !== "" &&
          hops[i]?.ipeeInfo?.country !== route[route.length - 1]
        ) {
          route = [...route, hops[i].ipeeInfo.country];
        }
      }
    } catch (error) {
      console.log(error);
      error = error.message;
    } finally {
      loading = false;
    }
  }

  EventsOn("hop", (hop: Hop) => {
    hops[hop.number] = hop;
    hopsEelement?.lastElementChild?.scrollIntoView({ behavior: "smooth" });
  });

  EventsOn("hop info", (hop: Hop) => {
    hops[hop.number] = hop;
    // if (
    //   hop.ipeeInfo.country !== "" &&
    //   hop.ipeeInfo.country !== route[route.length - 1]
    // ) {
    //   route = [...route, hop.ipeeInfo.country];
    // }
  });

  EventsOn("log", (message) => {
    logs = [...logs, message];
  });

  onMount(async () => {
    try {
      protocol.onchange = () => {
        protocolValue = protocol.value;
      };
      ip.value = "85.15.17.13";
      maxHops.value = "32";
      timeout.value = "1000";
      destinationPort.value = "80";
      mss.value = "1460";
      version = await GetVersion();
      const temp = await GetPublicIP();
      if (temp.startsWith("error")) {
        error = temp.slice(5);
        publicIP = "Unknown";
      } else publicIP = temp;
      const res = await GetInterfaces();
      for (let i = 0; i < res.length; i++) interfaces.push(res[i]);
      interfaces = [...interfaces];
      await sleep(500);
      bindOn.selectIndex(0);
    } catch (error) {
      console.log(error);
    }
  });
</script>

<div class="relative h-svh bg-dark-surface text-dark-onSurface">
  <!-- version and public ip -->
  <div
    class="w-full flex justify-between fixed bottom-0 text-sm bg-dark-surface z-10"
  >
    <!-- version -->
    <div class="m-4">
      v{version}
    </div>

    <!-- public ip -->
    <div class="m-4">
      {publicIP}
    </div>
  </div>

  <!-- navbar -->
  <nav class=" border-b-dark-surfaceBright border-b p-4">
    <!-- svelte-ignore a11y-click-events-have-key-events -->
    <md-filled-button on:click={() => (showLogs = true)} class="nav-button"
      >Logs</md-filled-button
    >
    <!-- svelte-ignore a11y-click-events-have-key-events -->
    <md-filled-button on:click={() => (showLogs = false)} class="nav-button"
      >Trace</md-filled-button
    >
  </nav>

  {#key showLogs}
    <div in:fade={{ duration: 300, delay: 300 }} out:fade={{ duration: 300 }}>
      {#if showLogs}
        <div class="grid grid-cols-1 gap-2 m-4 pb-20">
          {#each logs as l}
            <div
              class="border-dark-surfaceBright border-[1px] rounded-xl px-4 py-2 text-sm"
            >
              {l}
            </div>
          {/each}
        </div>
      {:else}
        <!-- inputs -->
        <form
          action="#"
          on:submit|preventDefault
          class="grid grid-cols-6 bg-dark-surface items-center gap-4 p-4 w-full mx-auto sticky top-0 shadow"
        >
          <md-outlined-text-field
            bind:this={ip}
            label="Destination"
            disabled={loading}
            class="col-span-2 grid"
          />
          <md-outlined-select
            label="Protocol"
            bind:this={protocol}
            disabled={loading}
            class="col-span-2"
          >
            <md-select-option value="icmp" selected>ICMP</md-select-option>
            <md-select-option value="tcp">TCP</md-select-option>
          </md-outlined-select>
          <md-outlined-text-field
            bind:this={maxHops}
            label="Max Hops"
            disabled={loading}
          />
          <md-outlined-text-field
            bind:this={timeout}
            label="Timeout"
            disabled={loading}
          />
          <md-outlined-select
            label="Interface"
            bind:this={bindOn}
            disabled={loading}
            class="col-span-2"
            id="interface"
          >
            {#each interfaces as i}
              <md-select-option value={i[0]}>
                <div class="font-bold">{i[0]}</div>
                <div class="text-sm">{i[1]}</div>
              </md-select-option>
            {/each}
          </md-outlined-select>
          <md-outlined-text-field
            bind:this={destinationPort}
            label="Dst Port"
            disabled={loading}
            class={protocolValue !== "tcp" && "hidden"}
          />
          <md-outlined-text-field
            bind:this={mss}
            label="MSS"
            disabled={loading}
            class={protocolValue !== "tcp" && "hidden"}
          />
          <div class="col-span-6 flex justify-end">
            <!-- svelte-ignore a11y-click-events-have-key-events -->
            <md-filled-button
              on:click={() => {
                if (loading) StopTrace();
                else trace();
              }}>{loading ? "CANCEL" : "TRACE"}</md-filled-button
            >
          </div>
        </form>

        <!-- error message -->
        {#if error}
          <div
            class="mx-4 mb-4 xl:w-fit px-4 py-2 rounded-xl shadow bg-dark-errorContainer text-dark-onErrorContainer"
          >
            {error}
          </div>
        {/if}

        <!-- table -->
        <div bind:this={hopsEelement} class="w-full rounded-xl pb-32">
          <!-- table head -->
          <div
            class="text-lg mx-4 grid grid-cols-12 grid-flow-col gap-1 border-b pb-2 mb-2 border-dark-surfaceContainer"
          >
            <span class="col-span-1">#</span>
            <span class="col-span-3">Address</span>
            <span class="col-span-2">RTT</span>
            <span class="col-span-2">Country</span>
            <span class="col-span-4">ISP</span>
          </div>
          {#each Object.values(hops) as hop}
            <div
              class="grid grid-cols-12 grid-flow-col gap-1 mx-4 my-1 {(hop.address ===
                ip.value ||
                hop.address === lastSuccessfulDestination) &&
                'text-dark-primary text-lg'}"
              transition:fly={{ duration: 100, y: 10 }}
            >
              <!-- hop number -->
              <span class="col-span-1">
                {hop.number}
              </span>
              <!-- src -->
              <span class="col-span-3 flex">
                {hop.timedOut
                  ? "*"
                  : hop.address === ip.value && protocol.value === "tcp"
                    ? `${hop.address}:${destinationPort.value}`
                    : hop.address}
              </span>
              <!-- rtt -->
              <span class="col-span-2">
                {hop.timedOut ? "*" : `${hop.rtt}ms`}
              </span>
              <!-- country -->
              <span class="col-span-2 truncate flex items-center">
                {#if hop.timedOut || hop.isPrivate}
                  *
                {:else if hop.ipeeInfo.countryCode}
                  {hop.ipeeInfo.countryCode}
                {:else}
                  <md-circular-progress indeterminate />
                {/if}
              </span>
              <!-- isp -->
              <span class="col-span-4 truncate flex items-center">
                {#if hop.timedOut || hop.isPrivate}
                  *
                {:else if hop.ipeeInfo.organizationName}
                  {hop.ipeeInfo.organizationName}
                {:else}
                  <md-circular-progress indeterminate />
                {/if}
              </span>
            </div>
          {/each}
          {#if loading}
            {#key Object.keys(hops).length}
              <div class="w-full mt-6 h-1"></div>
            {/key}
          {/if}
        </div>

        <!-- countries -->
        {#if route.length}
          <div
            transition:fly
            class="bg-dark-tertiary w-full shadow p-4 fixed bottom-12 text-sm text-dark-onTertiary"
          >
            {#each route as country}
              <span>→</span><span class="mx-2">{country}</span>
            {/each}
          </div>
        {/if}
      {/if}
    </div>
  {/key}
</div>

<style>
  :root {
    --md-circular-progress-size: 24px;
  }
  #interface {
    --md-outlined-select-text-field-input-text-size: 12px;
  }
  .nav-button {
    --md-filled-button-label-text-size: 12px;
    --md-filled-button-container-shape: 4px;
  }
</style>
