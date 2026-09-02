/**
 * Types for guacamole-common-js.
 *
 * The library ships as plain JavaScript with no bundled types. Declared locally
 * rather than pulling `@types/guacamole-common-js` so that the surface we depend
 * on is written down, exactly, next to the code that uses it -- and so the build
 * has one fewer version to resolve. If the DefinitelyTyped package is added later,
 * delete this file; keeping both would declare the module twice.
 *
 * Only what the RDP pane actually touches is declared. Everything omitted is
 * omitted on purpose.
 */
declare module 'guacamole-common-js' {
  /**
   * The transport a Client reads instructions from.
   *
   * Declared as a class with assignable handler properties because that is how the
   * library models it: a tunnel implementation sets `oninstruction` and friends,
   * and Client overwrites them when it connects.
   */
  export class Tunnel {
    uuid: string | null
    state: number
    receiveTimeout: number
    connect(data?: string): void
    disconnect(): void
    sendMessage(...elements: Array<string | number>): void
    isConnected(): boolean
    oninstruction: ((opcode: string, args: string[]) => void) | null
    onstatechange: ((state: number) => void) | null
    onerror: ((status: Status) => void) | null
    onuuid: ((uuid: string) => void) | null
  }

  /**
   * Connection lifecycle, mirroring Guacamole.Tunnel.State.
   *
   * Declared after the class, not before it: a namespace that merges with a class
   * has to follow it, and the same ordering is used for Mouse below.
   */
  export namespace Tunnel {
    export const CONNECTING: number
    export const OPEN: number
    export const CLOSED: number
    export const UNSTABLE: number
  }

  /** Splits a byte/character stream into instructions. */
  export class Parser {
    receive(packet: string, isBuffer?: boolean): void
    oninstruction: ((opcode: string, args: string[]) => void) | null
  }

  export class Status {
    code: number
    message?: string
    constructor(code: number, message?: string)
    isError(): boolean
  }

  export class Layer {
    width: number
    height: number
    getCanvas(): HTMLCanvasElement
  }

  export class Display {
    getElement(): HTMLElement
    getWidth(): number
    getHeight(): number
    getScale(): number
    scale(scale: number): void
    getDefaultLayer(): Layer
    showCursor(shown: boolean): void
    onresize: ((width: number, height: number) => void) | null
  }

  export class OutputStream {
    sendBlob(data: string): void
    sendEnd(): void
  }

  export class InputStream {
    sendAck(message: string, code: number): void
  }

  export class StringReader {
    constructor(stream: InputStream)
    ontext: ((text: string) => void) | null
    onend: (() => void) | null
  }

  export class StringWriter {
    constructor(stream: OutputStream)
    sendText(text: string): void
    sendEnd(): void
  }

  export class Client {
    constructor(tunnel: Tunnel)
    connect(data?: string): void
    disconnect(): void
    getDisplay(): Display
    sendKeyEvent(pressed: number, keysym: number): void
    sendMouseState(state: Mouse.State): void
    sendSize(width: number, height: number): void
    createClipboardStream(mimetype: string): OutputStream
    onstatechange: ((state: number) => void) | null
    onerror: ((status: Status) => void) | null
    onname: ((name: string) => void) | null
    onclipboard: ((stream: InputStream, mimetype: string) => void) | null
  }

  export class Mouse {
    constructor(element: HTMLElement | Document)
    onmousedown: ((state: Mouse.State) => void) | null
    onmouseup: ((state: Mouse.State) => void) | null
    onmousemove: ((state: Mouse.State) => void) | null
    onmouseout: (() => void) | null
  }

  export namespace Mouse {
    export class State {
      x: number
      y: number
      left: boolean
      middle: boolean
      right: boolean
      up: boolean
      down: boolean
      constructor(
        x: number,
        y: number,
        left: boolean,
        middle: boolean,
        right: boolean,
        up: boolean,
        down: boolean,
      )
    }
  }

  export class Keyboard {
    constructor(element?: HTMLElement | Document | null)
    onkeydown: ((keysym: number) => boolean | void) | null
    onkeyup: ((keysym: number) => void) | null
    listenTo(element: HTMLElement | Document): void
    reset(): void
  }
}
