package com.clsoft.netguard.engine.detector.tf


import android.content.Context
import org.tensorflow.lite.Interpreter
import java.nio.MappedByteBuffer
import java.nio.channels.FileChannel

object ModelLoader {
    fun loadModel(context: Context, assetName: String): Interpreter {
        val bb = loadMapped(context, assetName)
        val options = Interpreter.Options().apply { setNumThreads(2) }
        return Interpreter(bb, options)
    }


    private fun loadMapped(context: Context, assetName: String): MappedByteBuffer {
        val afd = context.assets.openFd(assetName)
        val input = java.io.FileInputStream(afd.fileDescriptor)
        val channel = input.channel
        return channel.map(FileChannel.MapMode.READ_ONLY, afd.startOffset, afd.length)
    }
}